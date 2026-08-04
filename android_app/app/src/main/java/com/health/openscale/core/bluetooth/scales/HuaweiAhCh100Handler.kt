/*
 * openScale
 * Copyright (C) 2026 openScale contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.health.openscale.core.bluetooth.scales

import com.health.openscale.R
import com.health.openscale.core.bluetooth.data.ScaleMeasurement
import com.health.openscale.core.bluetooth.data.ScaleUser
import com.health.openscale.core.bluetooth.libs.EtekcityLib
import com.health.openscale.core.service.ScannedDeviceInfo
import java.io.ByteArrayOutputStream
import java.security.GeneralSecurityException
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.Timer
import java.util.TimerTask
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

/**
 * Huawei AH100 / CH100 body-fat scale handler.
 *
 * The two products use the same Chipsea CST34M97-based hardware with an
 * identical wire protocol and only differ in the BLE advertisement name
 * (`AH100` vs `CH100`); [supportFor] matches either.
 *
 * The wire-protocol primitives — XOR obfuscation, AES-CTR, frame builders
 * and the measurement parser — are the [Companion] object at the bottom of
 * this file. They are pure Kotlin (no Android dependencies), so the parsing
 * logic is locked by the JVM unit tests in `HuaweiAhCh100HandlerTest` and we
 * don't have to re-prove it on a real scale.
 *
 * History (so future maintainers don't repeat past mistakes):
 *
 *  - openScale **v2.5.4** had a working Java handler, but only parsed the
 *    first half of the two-part measurement frame. The Huawei app decrypts
 *    both 16-byte halves independently, reconstructs the payload, and then
 *    removes the MAC XOR layer.
 *  - The 3.x Kotlin rewrite (commit 2e7e708f and follow-ups) accidentally
 *    dropped the AES decryption entirely and replaced the byte layout with
 *    invented offsets. That produced the 138 kg / 180 % / year-3084 nonsense
 *    reported in #1206 / #1280.
 *  - Issue #1276 proposed a partial fix (decrypt the merged buffer instead
 *    of the first half) which is mathematically equivalent for the first 16
 *    bytes — but the contributor's account was deleted before it landed.
 *  - This handler follows the Huawei app's paired-frame behaviour. It uses
 *    the default BLE tuning profile (Balanced, MTU bumped to 185); the
 *    protocol still delivers two logical encrypted blocks.
 *  - Real-world note: when migrating from openScale 2.5.x or Huawei Health
 *    on the same phone, users may need to "Forget" the scale once in the
 *    Android Bluetooth settings. The link-layer encryption keys from the
 *    previous bond don't survive this protocol's re-pair flow and otherwise
 *    cause `CONNECTION_TERMINATED_MIC_FAILURE` after the first command.
 */
class HuaweiAhCh100Handler : ScaleDeviceHandler() {

    // --- Identifiers --------------------------------------------------------

    private val SERVICE = uuid16(0xFAA0)
    private val CHAR_TX = uuid16(0xFAA1) // host -> scale: write
    private val CHAR_RX = uuid16(0xFAA2) // scale -> host: notify

    /**
     * BLE advertisement name -> UI display name. Both products use the same
     * Chipsea CST34M97 hardware, so one handler serves both.
     */
    private val supportedAdverts = mapOf(
        "AH100" to "Huawei AH100",
        "CH100" to "Huawei CH100",
    )

    // We need the scale MAC for the XOR obfuscation. Cache it from
    // ScannedDeviceInfo.address as soon as supportFor() approves.
    private var sessionMac: String? = null

    private fun macBytes(): ByteArray {
        val s = sessionMac
        if (s.isNullOrBlank()) {
            logW("sessionMac is null/blank; XOR-obfuscation will be a no-op and frames will not parse")
            return ByteArray(6)
        }
        return runCatching { macStringToBytes(s) }
            .onFailure { logW("Failed to parse sessionMac '$s': ${it.message}") }
            .getOrElse { ByteArray(6) }
    }

    override fun supportFor(device: ScannedDeviceInfo): DeviceSupport? {
        // Some Huawei firmware revisions append trailing NULs / whitespace to
        // the advert name, and some Honor / OEM rebrands prefix the vendor
        // name. Strip those so our match is robust without overshooting into
        // the CH100S handler's territory.
        val raw = device.name
        val cleaned = raw
            .replace("\u0000", "")
            .trim()
            .uppercase(Locale.US)
        val candidates = setOf(
            cleaned,
            cleaned.removePrefix("HUAWEI ").trim(),
            cleaned.removePrefix("HONOR ").trim(),
            cleaned.substringBefore('-'),
            cleaned.substringBefore('_'),
            cleaned.substringBefore(' ')
        )
        val matchedAdvert = supportedAdverts.keys.firstOrNull { it in candidates } ?: return null
        if (cleaned != raw) {
            logD("supportFor: matched advert '$raw' -> '$cleaned' as '$matchedAdvert'")
        }

        sessionMac = device.address

        val caps = setOf(
            DeviceCapability.BODY_COMPOSITION,
            DeviceCapability.TIME_SYNC,
            DeviceCapability.USER_SYNC,
            DeviceCapability.HISTORY_READ
        )
        val implemented = setOf(
            DeviceCapability.BODY_COMPOSITION,
            DeviceCapability.TIME_SYNC,
            DeviceCapability.USER_SYNC,
            DeviceCapability.HISTORY_READ
        )
        return DeviceSupport(
            displayName = supportedAdverts.getValue(matchedAdvert),
            capabilities = caps,
            implemented = implemented,
            linkMode = LinkMode.CONNECT_GATT
        )
    }

    // --- Session state ------------------------------------------------------

    private var authCode: ByteArray = ByteArray(0)
    private var magicKey: ByteArray? = null
    private var triesAuth = 0
    @Volatile private var authorised = false
    private var scaleAwake = false
    private var scaleBound = false
    private var sessionUser: ScaleUser? = null
    private var lastMeasuredWeightTenthKg: Int = -1
    private var lastMeasuredImpedanceOhm: Int = -1
    @Volatile private var lastOutboundAtMs = 0L
    @Volatile private var heartbeatTimer: Timer? = null

    // First half of an encrypted measurement, awaiting its 0x8E/0x90 sibling.
    private var pendingFirst: ByteArray? = null
    private var pendingType: Byte = 0x00
    private var historyRequested = false
    private var historyActive = false

    // --- Lifecycle ---------------------------------------------------------

    override fun onConnected(user: ScaleUser) {
        stopHeartbeat()
        sessionUser = user.copy()
        val latestMeasurement = lastMeasurementFor(user.id)
        lastMeasuredWeightTenthKg = latestMeasurement
            ?.weight
            ?.takeIf { it.isFinite() && it > 0f }
            ?.let { (it * 10f).toInt() }
            ?: -1
        lastMeasuredImpedanceOhm = latestMeasurement
            ?.impedance
            ?.takeIf { it.isFinite() && it in 200.0..1500.0 }
            ?.toInt()
            ?: -1
        authCode = buildAuthToken(requireNotNull(sessionUser).id)
        triesAuth = 0
        authorised = false
        scaleAwake = false
        scaleBound = false
        magicKey = null
        pendingFirst = null
        pendingType = 0x00
        historyRequested = false
        historyActive = false

        setNotifyOn(SERVICE, CHAR_RX)
        userInfo(R.string.bt_info_step_on_scale)
    }

    override fun onDisconnected() {
        stopHeartbeat()
        authorised = false
        scaleAwake = false
        magicKey = null
        sessionUser = null
        pendingFirst = null
        pendingType = 0x00
        historyRequested = false
        historyActive = false
    }

    override fun onNotification(characteristic: UUID, data: ByteArray, user: ScaleUser) {
        if (characteristic != CHAR_RX || data.size < 3) return

        val op = data[2]
        // Plain notifications XOR their tail with the MAC; encrypted
        // measurement halves do too (then need an additional AES pass below).
        val deobfTail = deobfuscateTail(data, macBytes())

        logD("← op=0x%02X len=%d %s".format(op.toInt() and 0xFF, deobfTail.size, deobfTail.toHex(24)))

        when (op) {
            NTFY_WAKEUP -> {
                scaleAwake = true
                startHeartbeat()
                sendAuth()
            }

            NTFY_AUTH_RESULT -> {
                if (deobfTail.isNotEmpty() && deobfTail[0].toInt() == 1) {
                    authorised = true
                    triesAuth = 0
                    magicKey = deriveMagicKey(authCode, macBytes())
                    startHeartbeat()
                    if (!historyActive) historyRequested = false
                    sendGetVersion()
                    userInfo(R.string.bt_info_step_on_scale)
                } else {
                    if (triesAuth++ < 2) {
                        sendAuth()
                    } else {
                        // Fallback: BIND first, then AUTH again. The scale
                        // emits NTFY_BIND_OK on success which retries auth.
                        sendBind()
                    }
                }
            }

            NTFY_BIND_OK -> {
                scaleBound = true
                sendAuth()
            }

            NTFY_SCALE_VERSION -> sendSetUnit()

            NTFY_UNITS_SET -> sendSetTime()

            NTFY_SCALE_CLOCK ->
                sendUserInfo(requireNotNull(sessionUser), lastMeasuredWeightTenthKg.takeIf { it > 0 })

            NTFY_GO_SLEEP -> Unit

            NTFY_HISTORY_UPLOAD_DONE -> {
                historyActive = false
                historyRequested = false
                if (pendingType == NTFY_HISTORY_RECORD) {
                    pendingFirst = null
                    pendingType = 0x00
                }
            }

            // First halves of two-part encrypted measurement / history frame.
            NTFY_MEASUREMENT, NTFY_HISTORY_RECORD -> {
                if (data[0] == FRAME_NOTIFY_ENCRYPTED &&
                    (op != NTFY_HISTORY_RECORD || historyActive)
                ) {
                    pendingType = op
                    pendingFirst = data
                }
            }

            NTFY_MEASUREMENT2, NTFY_HISTORY_RECORD2 -> {
                if (data[0] == FRAME_NOTIFY_ENCRYPTED) {
                    val first = pendingFirst
                    val type = pendingType
                    pendingFirst = null
                    pendingType = 0x00
                    val expectedType = if (op == NTFY_MEASUREMENT2) NTFY_MEASUREMENT else NTFY_HISTORY_RECORD
                    if (first != null && type == expectedType) {
                        decodeAndPublish(first, data, type)
                    } else {
                        logW("Measurement second half did not match a pending first half")
                    }
                }
            }

            NTFY_MEASUREMENT_WEIGHT -> {
                // Stable-weight precursor; the encrypted pair carries the
                // composition we actually want. Ignore.
            }

            NTFY_USER_CHANGED -> {
                // The official app treats 0x20 as the USER_INFO/list-update
                // acknowledgement and starts the per-user history query here.
                if (authorised && !historyRequested) {
                    sendGetHistoryFirst()
                    historyRequested = true
                    historyActive = true
                } else {
                    logD("NTFY_USER_CHANGED received before auth or after history started; ignoring")
                }
            }

            else -> logD("Unhandled op 0x%02X".format(op.toInt() and 0xFF))
        }
    }

    private fun decodeAndPublish(first: ByteArray, second: ByteArray, type: Byte) {
        val isHistory = type == NTFY_HISTORY_RECORD
        val mk = magicKey
        val user = sessionUser
        if (mk == null || user == null || first.size < 19 || second.size < 19) {
            logW("Incomplete encrypted measurement pair or missing session state")
            return
        }
        val measurement = try {
            decodePair(first, second, mk, macBytes())
        } catch (e: GeneralSecurityException) {
            logW("AES-CTR failed on measurement: ${e.message}")
            return
        } catch (e: IllegalArgumentException) {
            logW("Measurement parse failed: ${e.message}")
            if (isHistory) sendGetHistoryNext()
            return
        }

        val published = publishMeasurement(measurement, user, isHistory)
        if (isHistory) {
            sendGetHistoryNext()
        } else if (published) {
            sendCmd(CMD_FAT_RESULT_ACK, byteArrayOf(0x00))
        }
    }

    private fun publishMeasurement(m: Measurement, user: ScaleUser, isHistory: Boolean): Boolean {
        val timestamp = m.dateTime ?: if (isHistory) {
            logW("History record has an invalid timestamp; dropping it")
            return false
        } else {
            Date()
        }
        lastMeasuredWeightTenthKg = (m.weightKg * 10f).toInt()
        lastMeasuredImpedanceOhm = m.impedanceOhm.takeIf { it in 200..1500 } ?: -1

        val sm = ScaleMeasurement().apply {
            this.userId = user.id
            this.dateTime = timestamp
            this.weight = m.weightKg
            this.fat = m.fatPct
            if (m.impedanceOhm in 1..3999) {
                this.impedance = m.impedanceOhm.toDouble()
                val lib = EtekcityLib(
                    gender = user.gender,
                    age = user.age,
                    weightKg = m.weightKg.toDouble(),
                    heightM = user.bodyHeight.toDouble() / 100.0,
                    impedance = m.impedanceOhm.toDouble()
                )
                this.water = lib.water.toFloat()
                this.muscle = lib.skeletalMusclePercentage.toFloat()
                this.bone = lib.boneMass.toFloat()
                this.bmr = lib.basalMetabolicRate.toFloat()
                this.visceralFat = lib.visceralFat.toFloat()
            }
        }
        publish(sm)
        logI(
            "Measurement: ${m.weightKg} kg, fat=${m.fatPct}%, impedance=${m.impedanceOhm} Ω, " +
                "userId=${user.id} (scale user ${m.userId}) @ ${ts(timestamp)} " +
                "(${if (isHistory) "history" else "live"})"
        )
        return true
    }

    // --- Commands ----------------------------------------------------------

    private fun sendAuth() = sendCmd(CMD_AUTH, authCode)

    private fun sendBind() = sendCmd(CMD_BIND_USER, authCode)

    private fun sendSetUnit() {
        // Protocol: 1 = kg, 2 = lb. We always tell the scale kg; openScale
        // converts to user units in the UI layer.
        sendCmd(CMD_SET_UNIT, byteArrayOf(0x01))
    }

    private fun sendSetTime() {
        val c = Calendar.getInstance()
        // [loYear, hiYear, month(1..12), day, hour, min, sec, dow(1..7 Mon..Sun)]
        val year = c.get(Calendar.YEAR)
        // Java DOW: SUN=1..SAT=7; protocol expects MON=1..SUN=7.
        val dow = ((c.get(Calendar.DAY_OF_WEEK) + 5) % 7) + 1
        val payload = byteArrayOf(
            (year and 0xFF).toByte(), ((year shr 8) and 0xFF).toByte(),
            (c.get(Calendar.MONTH) + 1).toByte(),
            c.get(Calendar.DAY_OF_MONTH).toByte(),
            c.get(Calendar.HOUR_OF_DAY).toByte(),
            c.get(Calendar.MINUTE).toByte(),
            c.get(Calendar.SECOND).toByte(),
            dow.toByte()
        )
        sendCmd(CMD_SET_SCALE_CLOCK, payload)
    }

    private fun sendUserInfo(user: ScaleUser, weightTenthKg: Int?) {
        // Official APK USER_INFO payload:
        //   auth(7) || age|sexBit(1) || height(1) || 0x00(1) || weightLE(2)
        //          || resistanceLE(2)
        // Total = 14 bytes.
        val sexBit = if (user.gender.isMale()) 0x00 else 0x80
        val age = (user.age and 0x7F) or sexBit
        val height = user.bodyHeight.toInt() and 0xFF
        val w = (weightTenthKg ?: (user.initialWeight * 10f).toInt()).coerceAtLeast(0)
        val tail = ByteArrayOutputStream().apply {
            write(byteArrayOf(age.toByte(), height.toByte(), 0x00))
            write(le16(w))
            write(le16(lastMeasuredImpedanceOhm.takeIf { it in 200..1500 } ?: 0xFFFF))
        }.toByteArray()

        val full = authCode + tail
        sendCmdEncrypted(full)
    }

    private fun sendGetVersion() = sendCmd(CMD_GET_VERSION, byteArrayOf())

    private fun sendGetHistoryFirst() {
        // Legacy: payload is auth || xor(auth), but lengthByte on wire is
        // 7 (legacy used "0x07 - 1" + 1 inside AHsendCommand → 0x07).
        val chk = xorChecksum(authCode)
        val pl = authCode + byteArrayOf(chk)
        val frame = buildPlainCommand(CMD_GET_RECORD, pl, macBytes(), explicitLen = 0x07)
        writeFrame(frame)
    }

    private fun sendGetHistoryNext() {
        sendCmd(CMD_GET_RECORD, byteArrayOf(0x01))
    }

    // --- Wire helpers ------------------------------------------------------

    /** Send a plain (non-encrypted) command. */
    private fun sendCmd(cmd: Byte, payload: ByteArray) {
        val frame = buildPlainCommand(cmd, payload, macBytes())
        logD("→ CMD 0x%02X len=%d (plain)".format(cmd.toInt() and 0xFF, payload.size))
        writeFrame(frame)
    }

    /** Send an AES-CTR encrypted command (USER_INFO). */
    private fun sendCmdEncrypted(payload: ByteArray) {
        val mk = magicKey ?: run {
            logW("magicKey missing; dropping encrypted cmd 0x%02X".format(CMD_USER_INFO.toInt() and 0xFF))
            return
        }
        val frame = buildEncryptedCommand(CMD_USER_INFO, payload, mk, macBytes())
        logD("→ CMD* 0x%02X len=%d (encrypted)".format(CMD_USER_INFO.toInt() and 0xFF, payload.size))
        writeFrame(frame)
    }

    private fun writeFrame(frame: ByteArray) {
        lastOutboundAtMs = System.nanoTime() / 1_000_000
        writeTo(SERVICE, CHAR_TX, frame, withResponse = true)
    }

    private fun startHeartbeat() {
        if (heartbeatTimer != null) return
        val timer = Timer("HuaweiAH100Heartbeat", true)
        heartbeatTimer = timer
        timer.scheduleAtFixedRate(object : TimerTask() {
            override fun run() {
                val idleMs = System.nanoTime() / 1_000_000 - lastOutboundAtMs
                if (authorised && idleMs >= HEARTBEAT_IDLE_MS) {
                    sendCmd(CMD_HEARTBEAT, byteArrayOf())
                }
            }
        }, HEARTBEAT_IDLE_MS, HEARTBEAT_CHECK_MS)
    }

    private fun stopHeartbeat() {
        heartbeatTimer?.cancel()
        heartbeatTimer = null
    }

    // --- Misc helpers ------------------------------------------------------

    private fun ts(d: Date): String = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(d)

    private fun ByteArray.toHex(maxBytes: Int): String {
        val sb = StringBuilder()
        val n = minOf(maxBytes, size)
        for (i in 0 until n) {
            if (i > 0) sb.append(' ')
            sb.append("%02X".format(this[i].toInt() and 0xFF))
        }
        if (size > n) sb.append(" …")
        return sb.toString()
    }

    // --- Wire protocol ------------------------------------------------------

    /**
     * Decoded measurement, as returned by [parseMeasurement].
     */
    internal data class Measurement(
        val userId: Int,
        val weightKg: Float,
        val fatPct: Float,
        val impedanceOhm: Int,
        val dateTime: Date?,
        val rawDecrypted: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Measurement

            if (userId != other.userId) return false
            if (weightKg != other.weightKg) return false
            if (fatPct != other.fatPct) return false
            if (impedanceOhm != other.impedanceOhm) return false
            if (dateTime != other.dateTime) return false
            if (!rawDecrypted.contentEquals(other.rawDecrypted)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = userId
            result = 31 * result + weightKg.hashCode()
            result = 31 * result + fatPct.hashCode()
            result = 31 * result + impedanceOhm
            result = 31 * result + (dateTime?.hashCode() ?: 0)
            result = 31 * result + rawDecrypted.contentHashCode()
            return result
        }
    }

    /**
     * Wire-protocol primitives for the Huawei AH100 / CH100 body-fat scale.
     *
     * This is a faithful Kotlin port of the v2.5.4 Java handler that was the
     * last known-good implementation (see openScale issues #1206, #1276, #1280
     * for the regression history in the 3.x rewrite). All bit-fiddling lives
     * here and is exercised by `HuaweiAhCh100HandlerTest`, so the
     * [HuaweiAhCh100Handler] BLE state machine above can stay focused on the
     * connection lifecycle.
     *
     * Protocol summary:
     * - Service 0xFAA0; write TX 0xFAA1; notify RX 0xFAA2.
     * - Every payload is XOR-obfuscated with the scale's BLE MAC (repeating
     *   6-byte key); see [obfuscate]. This is symmetric.
     * - Some commands and all measurement frames are additionally AES-CTR
     *   encrypted with a session-derived [deriveMagicKey] and the fixed
     *   [INITIAL_IV]. AES is also symmetric in CTR mode.
     * - Frames host->scale: `[start, lengthByte, cmd, ...obfuscated payload...]`
     *   - start = [FRAME_PLAIN] (0xDB) for non-encrypted commands. v2.5.4 wrote
     *     `lengthByte = payload.size + 1`. The 3.x rewrite changed this to
     *     `payload.size`, which appears to be one of the regressions.
     *   - start = [FRAME_ENCRYPTED] (0xDC) for encrypted commands (only USER_INFO
     *     in practice). v2.5.4 wrote `lengthByte = payload.size`.
     * - Frames scale->host: `[start, lengthByte, op, ...obfuscated tail...]`
     *   - start = [FRAME_NOTIFY_PLAIN] (0xBD) for plain notifications.
     *   - start = [FRAME_NOTIFY_ENCRYPTED] (0xBC) for both halves of an
     *     encrypted measurement / history record. The first half carries op
     *     0x0E (live) or 0x10 (history); the second half carries 0x8E / 0x90.
     *
     * Measurement decoding:
     * - Decrypt both 16-byte notification blocks independently with the IV
     *   reset for each block, concatenate them, then remove the continuous
     *   MAC XOR layer. This matches Huawei's official app.
     * - The resulting layout is documented on [parseMeasurement].
     */
    internal companion object {

        // ---------- Hard-coded keys / IV (v2.5.4) ------------------------------
        //
        // ByteArray is mutable so we keep the canonical bytes in private backing
        // fields and hand out fresh copies. Internal call sites work on the copy
        // they receive; mis-use by tests / future contributors cannot corrupt
        // the values for subsequent calls.

        private val INITIAL_KEY_BYTES: ByteArray =
            hexToBytes("3D A2 78 4A FB 87 B1 2A 98 0F DE 34 56 73 21 56")

        private val INITIAL_IV_BYTES: ByteArray =
            hexToBytes("4E F7 64 32 2F DA 76 32 12 3D EB 87 90 FE A2 19")

        /**
         * AES-128 key fragment. Returns a fresh copy on every access:
         * bytes [0..6] of `magicKey` come from the session (obfuscated auth
         * token); bytes [7..15] are the tail of this constant.
         */
        val INITIAL_KEY: ByteArray get() = INITIAL_KEY_BYTES.copyOf()

        /** AES-CTR IV. Returns a fresh copy on every access. */
        val INITIAL_IV: ByteArray get() = INITIAL_IV_BYTES.copyOf()

        // ---------- Frame start bytes -----------------------------------------

        /** Host->scale plain frame start (XOR-obfuscated payload only). */
        const val FRAME_PLAIN: Byte = 0xDB.toByte()

        /** Host->scale AES-encrypted frame start (USER_INFO etc). */
        const val FRAME_ENCRYPTED: Byte = 0xDC.toByte()

        /** Scale->host: first byte for the two halves of an encrypted measurement. */
        const val FRAME_NOTIFY_ENCRYPTED: Byte = 0xBC.toByte()

        /** Scale->host: first byte for plain notifications. */
        const val FRAME_NOTIFY_PLAIN: Byte = 0xBD.toByte()

        // ---------- Notification opcodes (data[2] from the scale) -------------

        const val NTFY_WAKEUP: Byte = 0x00
        const val NTFY_GO_SLEEP: Byte = 0x01
        const val NTFY_UNITS_SET: Byte = 0x02
        const val NTFY_SCALE_CLOCK: Byte = 0x08
        const val NTFY_SCALE_VERSION: Byte = 0x0C
        const val NTFY_MEASUREMENT: Byte = 0x0E
        const val NTFY_MEASUREMENT_WEIGHT: Byte = 0x0F
        const val NTFY_MEASUREMENT2: Byte = 0x8E.toByte()
        const val NTFY_HISTORY_RECORD: Byte = 0x10
        const val NTFY_HISTORY_RECORD2: Byte = 0x90.toByte()
        const val NTFY_HISTORY_UPLOAD_DONE: Byte = 0x19
        const val NTFY_USER_CHANGED: Byte = 0x20
        const val NTFY_AUTH_RESULT: Byte = 0x26
        const val NTFY_BIND_OK: Byte = 0x27

        // ---------- Command opcodes (cmd byte we send) ------------------------

        const val CMD_SET_UNIT: Byte = 2
        const val CMD_SET_SCALE_CLOCK: Byte = 8
        const val CMD_USER_INFO: Byte = 9
        const val CMD_GET_RECORD: Byte = 11
        const val CMD_GET_VERSION: Byte = 12
        const val CMD_FAT_RESULT_ACK: Byte = 19
        const val CMD_HEARTBEAT: Byte = 32
        const val CMD_AUTH: Byte = 36
        const val CMD_BIND_USER: Byte = 37

        private const val HEARTBEAT_IDLE_MS = 1_500L
        private const val HEARTBEAT_CHECK_MS = 500L

        // ---------- Primitives -----------------------------------------------

        /**
         * XOR every byte of [data] with the scale's MAC bytes (repeating).
         *
         * Self-inverse: `obfuscate(obfuscate(x, mac), mac) == x`.
         *
         * @param mac 6-byte BLE address in display order (i.e. for "AA:BB:CC:DD:EE:FF",
         *   the bytes [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).
         */
        fun obfuscate(data: ByteArray, mac: ByteArray): ByteArray {
            if (mac.isEmpty()) return data.copyOf()
            val out = data.copyOf()
            var m = 0
            for (i in out.indices) {
                if (m >= mac.size) m = 0
                out[i] = (out[i].toInt() xor (mac[m].toInt() and 0xFF)).toByte()
                m++
            }
            return out
        }

        /** AES/CTR/NoPadding. Symmetric: encrypt is the same operation as decrypt. */
        fun aesCtr(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("AES/CTR/NoPadding")
            val iv16 = ByteArray(16).apply { System.arraycopy(iv, 0, this, 0, min(16, iv.size)) }
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv16))
            return cipher.doFinal(data)
        }

        /** XOR checksum of [buf]'s bytes — used by AUTH token construction. */
        fun xorChecksum(buf: ByteArray, off: Int = 0, len: Int = buf.size): Byte {
            var x = 0
            for (i in off until (off + len)) x = x xor (buf[i].toInt() and 0xFF)
            return (x and 0xFF).toByte()
        }

        /**
         * Build the 7-byte AUTH token used in the handshake:
         *   `[0x11, 0x22, 0x33, 0x44, 0x55, chk, userId]`
         * where `chk` is chosen so the whole array XORs to zero.
         */
        fun buildAuthToken(userId: Int): ByteArray {
            val auth = byteArrayOf(0x11, 0x22, 0x33, 0x44, 0x55, 0x00, (userId and 0xFF).toByte())
            auth[5] = xorChecksum(auth)
            return auth
        }

        /**
         * Derive the AES-128 magicKey for the session.
         *
         * v2.5.4 layout: `obfuscate(authCode, mac) || INITIAL_KEY[7..15]`.
         * Result is always 16 bytes (7 + 9).
         */
        fun deriveMagicKey(authCode: ByteArray, mac: ByteArray): ByteArray {
            require(authCode.size == 7) { "authCode must be 7 bytes; got ${authCode.size}" }
            val obfAuth = obfuscate(authCode, mac)
            val tail = INITIAL_KEY_BYTES.copyOfRange(7, INITIAL_KEY_BYTES.size)
            return obfAuth + tail
        }

        // ---------- Frame writers --------------------------------------------

        /**
         * Build a host->scale plain command frame (start byte [FRAME_PLAIN]).
         *
         * IMPORTANT: matches v2.5.4's `lengthByte = payload.size + 1`. The 3.x
         * rewrite used `payload.size` which appears to break the AUTH handshake
         * on at least some firmware revisions and is one of the regressions
         * tracked by issues #1206 / #1280.
         *
         * @param explicitLen overrides the length byte (legacy callers used
         *   this for `GET_RECORD` to encode 0x06 even though payload was 7 bytes).
         */
        fun buildPlainCommand(
            cmd: Byte,
            payload: ByteArray,
            mac: ByteArray,
            explicitLen: Int? = null
        ): ByteArray {
            val len = explicitLen ?: (payload.size + 1)
            val header = byteArrayOf(FRAME_PLAIN, len.toByte(), cmd)
            return header + obfuscate(payload, mac)
        }

        /**
         * Build a host->scale AES-encrypted command frame (start byte
         * [FRAME_ENCRYPTED]).
         *
         * The official app MAC-XORs the plaintext, applies PKCS#7 padding,
         * then encrypts it. The length byte remains the unpadded payload size.
         */
        fun buildEncryptedCommand(
            cmd: Byte,
            payload: ByteArray,
            magicKey: ByteArray,
            mac: ByteArray,
            iv: ByteArray = INITIAL_IV
        ): ByteArray {
            val encrypted = aesCtr(pkcs7Pad(obfuscate(payload, mac)), magicKey, iv)
            val header = byteArrayOf(FRAME_ENCRYPTED, payload.size.toByte(), cmd)
            return header + encrypted
        }

        private fun pkcs7Pad(data: ByteArray): ByteArray {
            val padding = 16 - data.size % 16
            return data + ByteArray(padding) { padding.toByte() }
        }

        // ---------- Notification helpers -------------------------------------

        /**
         * Strip the 3-byte header and de-obfuscate the tail of a scale->host frame.
         * Returns the bytes that, for plain notifications, are the actual
         * payload, or, for the encrypted halves, the bytes that need to be
         * fed through [aesCtr] before parsing.
         */
        fun deobfuscateTail(frame: ByteArray, mac: ByteArray): ByteArray {
            if (frame.size <= 3) return ByteArray(0)
            return obfuscate(frame.copyOfRange(3, frame.size), mac)
        }

        // ---------- Measurement decoding -------------------------------------

        /**
         * Parse the v2.5.4 byte layout from already-decrypted measurement bytes.
         *
         * Layout (little-endian unless noted):
         * ```
         * [0]      userId (1..10)
         * [1..2]   weight in tenth-kg (uint16 LE)
         * [3..4]   fat in tenth-percent (uint16 LE)
         * [5..6]   year (uint16 LE)
         * [7]      month, 1..12
         * [8]      day
         * [9]      hour
         * [10]     minute
         * [11]     second
         * [12]     weekday (informational, ignored)
         * [13..14] resistance / impedance in ohm (uint16 LE)
         * ```
         */
        fun parseMeasurement(decrypted: ByteArray): Measurement {
            require(decrypted.size >= 15) {
                "decrypted frame must be at least 15 bytes; got ${decrypted.size}"
            }
            val userId = decrypted[0].toInt() and 0xFF
            val weightTenth = u16le(decrypted, 1)
            val fatTenth = u16le(decrypted, 3)
            val year = u16le(decrypted, 5)
            val month = decrypted[7].toInt() and 0xFF
            val day = decrypted[8].toInt() and 0xFF
            val hour = decrypted[9].toInt() and 0xFF
            val minute = decrypted[10].toInt() and 0xFF
            val second = decrypted[11].toInt() and 0xFF
            val impedance = u16le(decrypted, 13)

            require(weightTenth / 10f in 2.0f..350.0f) { "implausible weight" }
            require(fatTenth / 10f in 0.0f..75.0f) { "implausible body fat" }
            require(year in 2000..2099) { "implausible year" }

            val date: Date? = try {
                val cal = Calendar.getInstance().apply {
                    clear()
                    isLenient = false
                    set(year, month - 1, day, hour, minute, second)
                }
                cal.time
            } catch (_: Throwable) {
                null
            }

            return Measurement(
                userId = userId,
                weightKg = weightTenth / 10f,
                fatPct = fatTenth / 10f,
                impedanceOhm = impedance,
                dateTime = date,
                rawDecrypted = decrypted.copyOf()
            )
        }

        /**
         * Decode the two encrypted notification blocks exactly as Huawei's app:
         * AES-CTR each 16-byte block with a fresh IV, concatenate, then remove
         * the MAC XOR layer over the complete 32-byte payload.
         */
        fun decodePair(
            firstHalfFrame: ByteArray,
            secondHalfFrame: ByteArray,
            magicKey: ByteArray,
            mac: ByteArray
        ): Measurement {
            require(firstHalfFrame.size >= 19 && secondHalfFrame.size >= 19) {
                "encrypted measurement halves must each contain 16 payload bytes"
            }
            val first = aesCtr(firstHalfFrame.copyOfRange(3, 19), magicKey, INITIAL_IV)
            val second = aesCtr(secondHalfFrame.copyOfRange(3, 19), magicKey, INITIAL_IV)
            return parseMeasurement(obfuscate(first + second, mac))
        }

        // ---------- Internal utils -------------------------------------------

        fun u16le(b: ByteArray, off: Int): Int =
            (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8)

        fun le16(v: Int): ByteArray =
            byteArrayOf((v and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte())

        fun hexToBytes(s: String): ByteArray {
            val clean = s.replace(" ", "").replace(":", "").replace("-", "")
            val even = if (clean.length % 2 == 0) clean else "0$clean"
            return ByteArray(even.length / 2) { i ->
                even.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        }

        /** Convert "AA:BB:CC:DD:EE:FF" (or no separators) to 6 bytes in display order. */
        fun macStringToBytes(mac: String): ByteArray {
            val clean = mac.replace(":", "").replace("-", "")
            require(clean.length == 12) { "MAC must be 12 hex chars; got $mac" }
            return ByteArray(6) { i ->
                clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        }
    }
}

/*
 * openScale
 * Copyright (C) 2025 olie.xdev <olie.xdeveloper@googlemail.com>
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

import android.os.SystemClock
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
 * Honor Smart Scale CH100S body fat scale (Chipsea CST34M97 chipset).
 *
 * Protocol reverse-engineered from the Huawei Body Fat Scale companion app
 * (com.huawei.overseas.ah100) and verified by BLE packet capture.
 *
 * Key differences from the CH100 (AH100):
 * - Measurement frames are AES-CTR encrypted (using the initial key, IV resets per packet).
 * - After AES decryption + MAC-XOR, the frame layout is:
 *     [userId, weightLE(2), fatLE(2), yearLE(2), month, day, hour, min, sec, dow, impedanceLE(2)]
 * - USER_INFO (CMD 0x09) is encrypted with MAC-XOR first, then AES-CTR (initial key).
 * - Body composition (water%, muscle%, bone, BMR, visceral fat) is computed app-side
 *   from impedance using BIA formulas, as the scale only transmits weight, fat%, and impedance.
 */
class HuaweiCH100SHandler : ScaleDeviceHandler() {

    // --- BLE identifiers ------------------------------------------------------

    private val SERVICE = uuid16(0xFAA0)
    private val CHAR_TX = uuid16(0xFAA1)
    private val CHAR_RX = uuid16(0xFAA2)

    private var sessionMac: String? = null

    override fun supportFor(device: ScannedDeviceInfo): DeviceSupport? {
        val name = device.name.uppercase(Locale.US)
        if (name != "CH100S") return null

        sessionMac = device.address

        val caps = setOf(
            DeviceCapability.BODY_COMPOSITION,
            DeviceCapability.TIME_SYNC,
            DeviceCapability.USER_SYNC,
            DeviceCapability.HISTORY_READ
        )
        return DeviceSupport(
            displayName = "Honor Smart Scale (CH100S)",
            capabilities = caps,
            implemented = setOf(
                DeviceCapability.BODY_COMPOSITION,
                DeviceCapability.TIME_SYNC,
                DeviceCapability.USER_SYNC,
                DeviceCapability.HISTORY_READ
            ),
            linkMode = LinkMode.CONNECT_GATT
        )
    }

    // --- Crypto constants -----------------------------------------------------

    private val AES_KEY = hexToBytes("3D A2 78 4A FB 87 B1 2A 98 0F DE 34 56 73 21 56")
    private val AES_IV  = hexToBytes("4E F7 64 32 2F DA 76 32 12 3D EB 87 90 FE A2 19")

    // --- Session state --------------------------------------------------------

    private var authCode: ByteArray = ByteArray(0)
    private var magicKey: ByteArray? = null
    private var triesAuth = 0
    private var authorised = false
    private var sessionUser: ScaleUser? = null
    @Volatile private var lastOutboundAtMs = 0L
    @Volatile private var heartbeatTimer: Timer? = null
    private var lastWeightTenthKg: Int = -1

    private var pendingType: Byte = 0x00
    private var pendingFirst: ByteArray? = null
    private var historyRequested = false
    private var historyActive = false

    // --- Notification opcodes -------------------------------------------------

    private val OP_WAKEUP       = 0x00.toByte()
    private val OP_SLEEP        = 0x01.toByte()
    private val OP_UNITS_SET    = 0x02.toByte()
    private val OP_CLOCK        = 0x08.toByte()
    private val OP_VERSION      = 0x0C.toByte()
    private val OP_MEAS_P1      = 0x0E.toByte()
    private val OP_MEAS_P2      = 0x8E.toByte()
    private val OP_HIST_P1      = 0x10.toByte()
    private val OP_HIST_P2      = 0x90.toByte()
    private val OP_HIST_DONE    = 0x19.toByte()
    private val OP_USER_CHANGED = 0x20.toByte()
    private val OP_AUTH_RESULT  = 0x26.toByte()
    private val OP_BIND_OK      = 0x27.toByte()

    // --- Commands -------------------------------------------------------------

    private val CMD_SET_UNIT    = 2.toByte()
    private val CMD_SET_CLOCK   = 8.toByte()
    private val CMD_USER_INFO   = 9.toByte()
    private val CMD_GET_RECORD  = 11.toByte()
    private val CMD_GET_VERSION = 12.toByte()
    private val CMD_FAT_ACK     = 19.toByte()
    private val CMD_HEARTBEAT   = 32.toByte()
    private val CMD_AUTH        = 36.toByte()
    private val CMD_BIND        = 37.toByte()

    // --- Lifecycle ------------------------------------------------------------

    override fun onConnected(user: ScaleUser) {
        sessionUser = user.copy()
        authCode = buildAuthToken(requireNotNull(sessionUser).id)
        setNotifyOn(SERVICE, CHAR_RX)
        triesAuth = 0
        authorised = false
        magicKey = null
        lastOutboundAtMs = 0L
        stopHeartbeat()
        pendingType = 0x00
        pendingFirst = null
        historyRequested = false
        historyActive = false
        userInfo(R.string.bt_info_step_on_scale)
    }

    override fun onNotification(characteristic: UUID, data: ByteArray, user: ScaleUser) {
        if (characteristic != CHAR_RX || data.size < 3) return
        if (data[0] == 0xBD.toByte() && data.size != ((data[1].toInt() and 0xFF) + 3)) {
            logD("Ignoring malformed CH100S control frame len=${data.size} declared=${data[1].toInt() and 0xFF}")
            return
        }
        val op = data[2]
        val payload = macXor(data.copyOfRange(3, data.size))

        when (op) {
            OP_WAKEUP -> {
                if (!authorised) {
                    magicKey = concat(macXor(authCode), AES_KEY.copyOfRange(7, AES_KEY.size))
                    sendPlain(CMD_AUTH, authCode)
                }
            }

            OP_AUTH_RESULT -> {
                if (payload.isNotEmpty() && payload[0].toInt() == 1) {
                    authorised = true
                    val obfAuth = macXor(authCode)
                    val keyTail = AES_KEY.copyOfRange(7, AES_KEY.size)
                    magicKey = concat(obfAuth, keyTail)
                    startHeartbeat()
                    sendPlain(CMD_GET_VERSION, byteArrayOf())
                    userInfo(R.string.bt_info_step_on_scale)
                } else {
                    if (triesAuth++ < 2) sendPlain(CMD_AUTH, authCode)
                    else sendPlain(CMD_BIND, authCode)
                }
            }

            OP_VERSION -> sendPlain(CMD_SET_UNIT, byteArrayOf(0x01))

            OP_UNITS_SET -> sendSetTime()

            OP_CLOCK -> sendUserInfo(requireNotNull(sessionUser), lastWeightTenthKg.takeIf { it > 0 })

            OP_USER_CHANGED -> {
                logD("CH100S user info/list update ack")
                if (authorised && !historyRequested) {
                    historyRequested = true
                    historyActive = true
                    sendGetHistoryFirst()
                }
            }

            OP_MEAS_P1, OP_HIST_P1 -> {
                if (data[0] == 0xBC.toByte() && (op == OP_MEAS_P1 || historyActive)) {
                    pendingType = op
                    pendingFirst = data
                }
            }

            OP_MEAS_P2, OP_HIST_P2 -> {
                if (data[0] == 0xBC.toByte()) {
                    val first = pendingFirst
                    val type = pendingType
                    pendingFirst = null
                    pendingType = 0x00
                    val expectedType = if (op == OP_MEAS_P2) OP_MEAS_P1 else OP_HIST_P1
                    if (first != null && type == expectedType) {
                        handleEncryptedPair(first, data, type)
                    } else {
                        logW("Measurement second half did not match a pending first half")
                    }
                }
            }

            OP_HIST_DONE -> {
                historyActive = false
                if (pendingType == OP_HIST_P1) {
                    pendingType = 0x00
                    pendingFirst = null
                }
                logD("CH100S history upload complete")
            }

            OP_BIND_OK -> { /* ack */ }

            OP_SLEEP -> stopHeartbeat()

            else -> logD("Unhandled op 0x%02X".format(op))
        }
    }

    // --- Measurement decryption & parsing ------------------------------------

    private fun handleEncryptedPair(first: ByteArray, second: ByteArray, type: Byte) {
        val key = magicKey
        if (key == null || first.size < 19 || second.size < 19) {
            logW("Incomplete encrypted measurement pair or missing session key")
            return
        }
        val rawP1 = first.copyOfRange(3, 19)
        val rawP2 = second.copyOfRange(3, 19)

        val decP1: ByteArray
        val decP2: ByteArray
        try {
            decP1 = aesCtr(rawP1, key)
            decP2 = aesCtr(rawP2, key)
        } catch (e: GeneralSecurityException) {
            logW("AES measurement decode failed: ${e.message}")
            return
        }

        val data = macXor(concat(decP1, decP2))
        logD("Decrypted (${data.size}b): ${hex(data, 0, min(data.size, 20))}…")

        when (type) {
            OP_MEAS_P1 -> {
                if (parseAndPublish(data)) sendPlain(CMD_FAT_ACK, byteArrayOf(0x00))
            }
            OP_HIST_P1 -> {
                parseAndPublish(data)
                sendPlain(CMD_GET_RECORD, byteArrayOf(0x01))
            }
        }
    }

    /**
     * Decrypted measurement frame layout (32 bytes, useful portion 0-14):
     *
     * | Offset | Field                | Encoding                    |
     * |--------|----------------------|-----------------------------|
     * | 0      | User ID              | uint8                       |
     * | 1-2    | Weight               | LE uint16, tenths of kg     |
     * | 3-4    | Body fat %           | LE uint16, tenths of %      |
     * | 5-6    | Year                 | LE uint16                   |
     * | 7      | Month                | uint8                       |
     * | 8      | Day                  | uint8                       |
     * | 9      | Hour                 | uint8                       |
     * | 10     | Minute               | uint8                       |
     * | 11     | Second               | uint8                       |
     * | 12     | Day of week          | uint8                       |
     * | 13-14  | Impedance            | LE uint16, ohms             |
     */
    private fun parseAndPublish(data: ByteArray): Boolean {
        if (data.size < 15) {
            logW("Frame too short: ${data.size}")
            return false
        }

        val userId    = data[0].toInt() and 0xFF
        val weight    = u16le(data, 1) / 10.0f
        val fat       = u16le(data, 3) / 10.0f
        val impedance = u16le(data, 13)
        val y = u16le(data, 5)
        val mo = data[7].toInt() and 0xFF
        val d = data[8].toInt() and 0xFF
        val h = data[9].toInt() and 0xFF
        val mi = data[10].toInt() and 0xFF
        val s = data[11].toInt() and 0xFF

        if (weight !in 2.0f..350.0f ||
            fat !in 0.0f..75.0f ||
            y !in 2000..2099 ||
            mo !in 1..12 ||
            d !in 1..31 ||
            h !in 0..23 ||
            mi !in 0..59 ||
            s !in 0..59
        ) {
            logW("Dropped implausible CH100S frame: ${frameSummary(data)}")
            return false
        }

        val dt = try {
            Calendar.getInstance().apply {
                clear()
                isLenient = false
                set(y, mo - 1, d, h, mi, s)
            }.time
        } catch (_: Exception) {
            logW("Dropped invalid CH100S calendar date: ${frameSummary(data)}")
            return false
        }

        lastWeightTenthKg = (weight * 10).toInt()
        val user = sessionUser ?: currentAppUser()

        val m = ScaleMeasurement().apply {
            this.userId = user.id
            this.dateTime = dt
            this.weight = weight
            this.fat = fat
            if (impedance in 1..3999) {
                this.impedance = impedance.toDouble()
                // Water%, muscle%, bone, BMR, visceral fat are not sent by the scale.
                // Compute app-side from impedance using BIA formulas (Chipsea chipset).
                val lib = EtekcityLib(
                    gender = user.gender,
                    age = user.age,
                    weightKg = weight.toDouble(),
                    heightM = user.bodyHeight.toDouble() / 100.0,
                    impedance = impedance.toDouble()
                )
                this.water = lib.water.toFloat()
                this.muscle = lib.skeletalMusclePercentage.toFloat()
                this.bone = lib.boneMass.toFloat()
                this.bmr = lib.basalMetabolicRate.toFloat()
                this.visceralFat = lib.visceralFat.toFloat()
            }
        }
        publish(m)
        logI("Measurement: $weight kg, fat=$fat%, imp=$impedance Ω, scaleUser=$userId appUser=${user.id} @ ${ts(dt)}")
        return true
    }

    // --- Commands -------------------------------------------------------------

    private fun sendSetTime() {
        val c = Calendar.getInstance()
        val year = c.get(Calendar.YEAR)
        sendPlain(CMD_SET_CLOCK, byteArrayOf(
            (year and 0xFF).toByte(), ((year shr 8) and 0xFF).toByte(),
            (c.get(Calendar.MONTH) + 1).toByte(),
            c.get(Calendar.DAY_OF_MONTH).toByte(),
            c.get(Calendar.HOUR_OF_DAY).toByte(),
            c.get(Calendar.MINUTE).toByte(),
            c.get(Calendar.SECOND).toByte(),
            (((c.get(Calendar.DAY_OF_WEEK) + 5) % 7) + 1).toByte()
        ))
    }

    private fun sendUserInfo(user: ScaleUser, weightTenthKg: Int?) {
        val sexBit = if (user.gender.isMale()) 0x00 else 0x80
        val age = user.age and 0x7F
        val w = (weightTenthKg ?: (user.initialWeight * 10f).toInt()).coerceAtLeast(0)
        val payload = ByteArrayOutputStream().apply {
            write(authCode)
            write((age or sexBit) and 0xFF)
            write(user.bodyHeight.toInt() and 0xFF)
            write(0x00)
            write(le16(w))
            write(le16(0xFFFF))
        }.toByteArray()
        sendEncrypted(CMD_USER_INFO, payload)
    }

    private fun sendGetHistoryFirst() {
        val checksum = authCode.fold(0) { acc, byte -> acc xor (byte.toInt() and 0xFF) }.toByte()
        val payload = authCode + checksum
        val packet = concat(byteArrayOf(0xDB.toByte(), 0x07, CMD_GET_RECORD), macXor(payload))
        lastOutboundAtMs = SystemClock.elapsedRealtime()
        writeTo(SERVICE, CHAR_TX, packet, withResponse = true)
    }

    // --- Wire helpers ---------------------------------------------------------

    private fun sendPlain(cmd: Byte, payload: ByteArray) {
        val header = byteArrayOf(0xDB.toByte(), (payload.size + 1).toByte(), cmd)
        val packet = concat(header, macXor(payload))
        lastOutboundAtMs = SystemClock.elapsedRealtime()
        writeTo(SERVICE, CHAR_TX, packet, withResponse = true)
    }

    private fun sendEncrypted(cmd: Byte, payload: ByteArray) {
        val obfuscated = macXor(payload)
        val key = magicKey ?: AES_KEY
        val enc = try { aesCtr(pkcs7Pad(obfuscated), key) } catch (e: GeneralSecurityException) {
            logW("AES encrypt: ${e.message}"); return
        }
        val header = byteArrayOf(0xDC.toByte(), payload.size.toByte(), cmd)
        val packet = concat(header, enc)
        lastOutboundAtMs = SystemClock.elapsedRealtime()
        writeTo(SERVICE, CHAR_TX, packet, withResponse = true)
    }

    private fun startHeartbeat() {
        if (heartbeatTimer != null) return
        val timer = Timer("HuaweiAH100Heartbeat", true)
        heartbeatTimer = timer
        timer.scheduleAtFixedRate(object : TimerTask() {
            override fun run() {
                if (!authorised) return
                val idleMs = SystemClock.elapsedRealtime() - lastOutboundAtMs
                if (idleMs >= HEARTBEAT_IDLE_MS) {
                    sendPlain(CMD_HEARTBEAT, byteArrayOf())
                }
            }
        }, HEARTBEAT_IDLE_MS, HEARTBEAT_CHECK_MS)
    }

    private fun stopHeartbeat() {
        heartbeatTimer?.cancel()
        heartbeatTimer = null
    }

    override fun onDisconnected() {
        stopHeartbeat()
        authorised = false
        magicKey = null
        sessionUser = null
        historyRequested = false
        historyActive = false
        pendingType = 0x00
        pendingFirst = null
    }

    // --- Crypto ---------------------------------------------------------------

    private fun macXor(raw: ByteArray): ByteArray {
        val mac = macStringToBytes(sessionMac ?: "00:00:00:00:00:00")
        if (mac.isEmpty()) return raw
        val out = raw.copyOf()
        for (i in out.indices) out[i] = (out[i].toInt() xor (mac[i % mac.size].toInt() and 0xFF)).toByte()
        return out
    }

    private fun aesCtr(data: ByteArray, key: ByteArray = AES_KEY): ByteArray {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(AES_IV))
        return cipher.doFinal(data)
    }

    private fun pkcs7Pad(data: ByteArray): ByteArray {
        val remainder = data.size % 16
        val pad = if (remainder == 0) 16 else 16 - remainder
        return data + ByteArray(pad) { pad.toByte() }
    }

    // --- Utils ----------------------------------------------------------------

    private fun buildAuthToken(appUserId: Int): ByteArray {
        val auth = byteArrayOf(0x11, 0x22, 0x33, 0x44, 0x55, 0x00, (appUserId and 0xFF).toByte())
        var x = 0; for (b in auth) x = x xor (b.toInt() and 0xFF)
        auth[5] = (x and 0xFF).toByte()
        return auth
    }

    private fun le16(v: Int) = byteArrayOf((v and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte())
    private fun u16le(b: ByteArray, o: Int) = (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)

    private fun macStringToBytes(mac: String): ByteArray {
        val clean = mac.replace(":", "").replace("-", "")
        if (clean.length != 12) return ByteArray(0)
        return ByteArray(6) { i -> clean.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    private fun hexToBytes(s: String): ByteArray {
        val c = s.replace(" ", "")
        return ByteArray(c.length / 2) { i -> c.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    private fun concat(a: ByteArray, b: ByteArray) =
        ByteArray(a.size + b.size).also {
            System.arraycopy(a, 0, it, 0, a.size)
            System.arraycopy(b, 0, it, a.size, b.size)
        }

    private fun hex(b: ByteArray, off: Int = 0, len: Int = b.size): String =
        (off until min(b.size, off + len)).joinToString(" ") { "%02X".format(b[it]) }

    private fun frameSummary(data: ByteArray): String {
        if (data.size < 15) return "short(${data.size})"
        return "user=${data[0].toInt() and 0xFF} " +
            "weight=${u16le(data, 1) / 10.0f} " +
            "fat=${u16le(data, 3) / 10.0f} " +
            "date=${u16le(data, 5)}-${data[7].toInt() and 0xFF}-${data[8].toInt() and 0xFF} " +
            "time=${data[9].toInt() and 0xFF}:${data[10].toInt() and 0xFF}:${data[11].toInt() and 0xFF} " +
            "imp=${u16le(data, 13)}"
    }

    private fun ts(d: Date) = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(d)

    private companion object {
        const val HEARTBEAT_IDLE_MS = 1500L
        const val HEARTBEAT_CHECK_MS = 500L
    }
}

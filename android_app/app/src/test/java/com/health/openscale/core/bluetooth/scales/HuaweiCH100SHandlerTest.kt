/*
 * openScale
 * Copyright (C) 2026 olie.xdev <olie.xdeveloper@googlemail.com>
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

import com.google.common.truth.Truth.assertThat
import com.health.openscale.core.bluetooth.data.ScaleMeasurement
import com.health.openscale.core.bluetooth.data.ScaleUser
import com.health.openscale.core.data.GenderType
import com.health.openscale.core.service.ScannedDeviceInfo
import com.welie.blessed.BluetoothPeripheral
import kotlinx.coroutines.CoroutineScope
import java.util.Calendar
import java.util.UUID
import kotlin.coroutines.EmptyCoroutineContext
import org.junit.Test

class HuaweiCH100SHandlerTest {

    @Test
    fun supportFor_acceptsCH100S() {
        val handler = HuaweiCH100SHandler()

        val support = handler.supportFor(
            ScannedDeviceInfo(
                name = "CH100S",
                address = macString,
                rssi = -50,
                serviceUuids = emptyList(),
                manufacturerData = null
            )
        )

        assertThat(support?.displayName).contains("CH100S")
    }

    @Test
    fun supportFor_rejectsAH100Alias() {
        val handler = HuaweiCH100SHandler()

        val support = handler.supportFor(
            ScannedDeviceInfo(
                name = "AH100",
                address = macString,
                rssi = -50,
                serviceUuids = emptyList(),
                manufacturerData = null
            )
        )

        assertThat(support).isNull()
    }

    @Test
    fun wakeup_sendsAuthWithHuaweiPlainCommandLength() {
        val fixture = Fixture()

        fixture.handler.handleConnected(fixture.user)
        fixture.transport.writes.clear()
        fixture.handler.handleNotification(charRx, byteArrayOf(0xBD.toByte(), 0x00, 0x00))

        val authPacket = fixture.transport.writes.single()

        assertThat(authPacket[0]).isEqualTo(0xDB.toByte())
        assertThat(authPacket[1]).isEqualTo(0x08.toByte())
        assertThat(authPacket[2]).isEqualTo(0x24.toByte())
    }

    @Test
    fun authSuccess_sendsGetVersionBeforeSetupCommands() {
        val fixture = Fixture()

        fixture.handler.handleConnected(fixture.user)
        fixture.handler.handleNotification(charRx, byteArrayOf(0xBD.toByte(), 0x00, 0x00))
        fixture.transport.writes.clear()

        fixture.handler.handleNotification(
            charRx,
            byteArrayOf(0xBD.toByte(), 0x01, 0x26, macXor(byteArrayOf(0x01), mac).single())
        )

        val version = fixture.transport.writes.single()

        assertThat(version[2]).isEqualTo(0x0C.toByte())
        assertThat(version[1]).isEqualTo(0x01.toByte())
    }

    @Test
    fun versionAck_sendsSetUnitBeforeClock() {
        val fixture = Fixture()

        fixture.authorise()
        fixture.transport.writes.clear()

        fixture.handler.handleNotification(
            charRx,
            byteArrayOf(
                0xBD.toByte(), 0x09, 0x0C,
                0xA3.toByte(), 0x35, 0xD2.toByte(), 0xBA.toByte(), 0x9F.toByte(),
                0xB8.toByte(), 0xA3.toByte(), 0x35, 0x46
            )
        )

        val setUnit = fixture.transport.writes.single()

        assertThat(setUnit[2]).isEqualTo(0x02.toByte())
        assertThat(setUnit[1]).isEqualTo(0x02.toByte())
    }

    @Test
    fun unitAck_sendsClockBeforeUserInfo() {
        val fixture = Fixture()

        fixture.authorise()
        fixture.handler.handleNotification(
            charRx,
            byteArrayOf(
                0xBD.toByte(), 0x09, 0x0C,
                0xA3.toByte(), 0x35, 0xD2.toByte(), 0xBA.toByte(), 0x9F.toByte(),
                0xB8.toByte(), 0xA3.toByte(), 0x35, 0x46
            )
        )
        fixture.transport.writes.clear()

        fixture.handler.handleNotification(
            charRx,
            byteArrayOf(0xBD.toByte(), 0x02, 0x02, 0x5D, 0xCB.toByte())
        )

        val setClock = fixture.transport.writes.single()

        assertThat(setClock[2]).isEqualTo(0x08.toByte())
        assertThat(setClock[1]).isEqualTo(0x09.toByte())
    }

    @Test
    fun clockAck_sendsUserInfoWithHuaweiLengths() {
        val fixture = Fixture()

        fixture.authorise()
        fixture.handler.handleNotification(
            charRx,
            byteArrayOf(
                0xBD.toByte(), 0x09, 0x0C,
                0xA3.toByte(), 0x35, 0xD2.toByte(), 0xBA.toByte(), 0x9F.toByte(),
                0xB8.toByte(), 0xA3.toByte(), 0x35, 0x46
            )
        )
        fixture.handler.handleNotification(
            charRx,
            byteArrayOf(0xBD.toByte(), 0x02, 0x02, 0x5D, 0xCB.toByte())
        )
        fixture.transport.writes.clear()

        fixture.handler.handleNotification(charRx, byteArrayOf(0xBD.toByte(), 0x00, 0x08))

        val userInfo = fixture.transport.writes.single()

        assertThat(userInfo[2]).isEqualTo(0x09.toByte())
        assertThat(userInfo[0]).isEqualTo(0xDC.toByte())
        assertThat(userInfo[1]).isEqualTo(0x0E.toByte())
        assertThat(userInfo.size).isEqualTo(19)
    }

    @Test
    fun userChangedAfterUserInfoAck_doesNotResendUserInfo() {
        val fixture = Fixture()

        fixture.authorise()
        fixture.handler.handleNotification(
            charRx,
            byteArrayOf(
                0xBD.toByte(), 0x09, 0x0C,
                0xA3.toByte(), 0x35, 0xD2.toByte(), 0xBA.toByte(), 0x9F.toByte(),
                0xB8.toByte(), 0xA3.toByte(), 0x35, 0x46
            )
        )
        fixture.handler.handleNotification(
            charRx,
            byteArrayOf(0xBD.toByte(), 0x02, 0x02, 0x5D, 0xCB.toByte())
        )
        fixture.handler.handleNotification(charRx, byteArrayOf(0xBD.toByte(), 0x00, 0x08))

        val userInfoWritesAfterClock = fixture.transport.writes.count { it[2] == 0x09.toByte() }

        fixture.handler.handleNotification(
            charRx,
            byteArrayOf(0xBD.toByte(), 0x01, 0x20, macXor(byteArrayOf(0x7D), mac).single())
        )

        assertThat(fixture.transport.writes.count { it[2] == 0x09.toByte() })
            .isEqualTo(userInfoWritesAfterClock)

        fixture.handler.handleNotification(
            charRx,
            byteArrayOf(0xBD.toByte(), 0x01, 0x20, macXor(byteArrayOf(0x7D), mac).single())
        )

        assertThat(fixture.transport.writes.count { it[2] == 0x09.toByte() })
            .isEqualTo(userInfoWritesAfterClock)
    }

    @Test
    fun malformedControlFrame_isIgnored() {
        val fixture = Fixture()

        fixture.authorise()
        fixture.transport.writes.clear()

        fixture.handler.handleNotification(
            charRx,
            byteArrayOf(0xBD.toByte(), 0x01, 0x00, 0x01, 0xCB.toByte())
        )

        assertThat(fixture.transport.writes).isEmpty()
    }

    @Test
    fun parseAndPublish_dropsImplausibleGarbageFrame() {
        val fixture = Fixture()
        val garbage = byteArrayOf(
            0x01,
            0xF5.toByte(), 0x98.toByte(),
            0xD3.toByte(), 0xB9.toByte(),
            0xC4.toByte(), 0x12,
            12, 14, 16, 29, 0, 1, 0, 0
        )

        fixture.invokeParseAndPublish(garbage)

        assertThat(fixture.published).isEmpty()
    }

    @Test
    fun parseAndPublish_publishesPlausibleFrame() {
        val fixture = Fixture()
        val valid = byteArrayOf(
            0x01,
            0xEE.toByte(), 0x02,
            0xC8.toByte(), 0x00,
            0xEA.toByte(), 0x07,
            5, 10, 12, 34, 56, 1,
            0xF4.toByte(), 0x01
        )

        fixture.invokeParseAndPublish(valid)

        assertThat(fixture.published).hasSize(1)
        assertThat(fixture.published.single().weight).isEqualTo(75.0f)
        assertThat(fixture.published.single().fat).isEqualTo(20.0f)
    }

    private class Fixture {
        val published = mutableListOf<ScaleMeasurement>()
        val user = ScaleUser(
            id = 7,
            birthday = Calendar.getInstance().apply { set(1991, Calendar.JANUARY, 2) }.time,
            bodyHeight = 180f,
            gender = GenderType.MALE,
            initialWeight = 75f
        )
        val handler = HuaweiCH100SHandler()
        val transport = CapturingTransport()

        init {
            handler.supportFor(
                ScannedDeviceInfo(
                    name = "CH100S",
                    address = macString,
                    rssi = -50,
                    serviceUuids = emptyList(),
                    manufacturerData = null
                )
            )
            handler.attach(
                transport = transport,
                callbacks = object : ScaleDeviceHandler.Callbacks {
                    override fun onPublish(measurement: ScaleMeasurement) {
                        published += measurement
                    }
                    override fun resolveString(resId: Int, vararg args: Any) = "res:$resId"
                },
                settings = object : ScaleDeviceHandler.DriverSettings {
                    override fun getInt(key: String, default: Int) = default
                    override fun putInt(key: String, value: Int) = Unit
                    override fun getString(key: String, default: String?) = default
                    override fun putString(key: String, value: String) = Unit
                    override fun remove(key: String) = Unit
                },
                data = object : ScaleDeviceHandler.DataProvider {
                    override fun currentUser() = user
                    override fun usersForDevice() = listOf(user)
                    override fun lastMeasurementFor(userId: Int): ScaleMeasurement? = null
                },
                scope = CoroutineScope(EmptyCoroutineContext)
            )
        }

        fun invokeParseAndPublish(data: ByteArray) {
            HuaweiCH100SHandler::class.java
                .getDeclaredMethod("parseAndPublish", ByteArray::class.java)
                .apply { isAccessible = true }
                .invoke(handler, data)
        }

        fun authorise() {
            handler.handleConnected(user)
            handler.handleNotification(charRx, byteArrayOf(0xBD.toByte(), 0x00, 0x00))
            handler.handleNotification(
                charRx,
                byteArrayOf(0xBD.toByte(), 0x01, 0x26, macXor(byteArrayOf(0x01), mac).single())
            )
        }
    }

    private class CapturingTransport : ScaleDeviceHandler.Transport {
        val writes = mutableListOf<ByteArray>()

        override fun setNotifyOn(service: UUID, characteristic: UUID) = Unit
        override fun write(
            service: UUID,
            characteristic: UUID,
            payload: ByteArray,
            withResponse: Boolean
        ) {
            writes += payload
        }

        override fun read(service: UUID, characteristic: UUID) = Unit
        override fun disconnect() = Unit
        override fun getPeripheral(): BluetoothPeripheral? = null
        override fun hasCharacteristic(service: UUID, characteristic: UUID) = true
    }

    private companion object {
        val charRx: UUID = UUID.fromString("0000faa2-0000-1000-8000-00805f9b34fb")
        const val macString = "A1:B2:C3:D4:E5:F6"
        val mac = byteArrayOf(
            0xA1.toByte(),
            0xB2.toByte(),
            0xC3.toByte(),
            0xD4.toByte(),
            0xE5.toByte(),
            0xF6.toByte()
        )

        fun macXor(raw: ByteArray, mac: ByteArray): ByteArray {
            val out = raw.copyOf()
            for (i in out.indices) {
                out[i] = (out[i].toInt() xor (mac[i % mac.size].toInt() and 0xFF)).toByte()
            }
            return out
        }
    }
}

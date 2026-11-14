package com.camctl.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TapoClientTest {
    private val pw = "Mon-Mot2Passe!é"

    private fun setup(mode: AuthMode, clientPw: String = pw): Pair<FakeCamera, TapoCamera> {
        val fake = FakeCamera(mode, pw)
        return fake to TapoCamera(TapoClient("192.168.1.42", clientPw, http = fake))
    }

    @Test fun legacy() = fullScenario(AuthMode.LEGACY)
    @Test fun secureV3() = fullScenario(AuthMode.SECURE_V3)
    @Test fun tpap() = fullScenario(AuthMode.TPAP)

    private fun fullScenario(mode: AuthMode) {
        val (fake, cam) = setup(mode)
        val info = cam.info()
        assertEquals(mode, cam.client.mode)
        assertEquals("C210", info.model)
        assertEquals("Salon", info.name)

        cam.move(10, -5)
        cam.step(180)
        assertEquals(listOf("10" to "-5", "step" to "180"), fake.moves)

        assertFalse(cam.privacy()); cam.setPrivacy(true); assertTrue(cam.privacy())
        val e = assertFailsWith<TapoException> { cam.move(1, 0) }
        assertEquals(-64324, e.code)
        cam.setPrivacy(false)

        assertTrue(cam.led()); cam.setLed(false); assertFalse(cam.led()); assertEquals("off", fake.state["led"])
        cam.setMotionDetection(false); assertFalse(cam.motionDetection())
        cam.setAutoTrack(true); assertTrue(cam.autoTrack())
        cam.setNightVision(TapoCamera.NightVision.INFRARED); assertEquals(TapoCamera.NightVision.INFRARED, cam.nightVision())

        assertEquals(listOf("Porte", "Jardin"), cam.presets().map { it.name })
        cam.savePreset("Allée"); assertEquals("Allée", cam.presets().last().name)
        cam.gotoPreset("2")
        cam.deletePreset("1"); assertEquals(listOf("Jardin", "Allée"), cam.presets().map { it.name })
        assertEquals(-64302, assertFailsWith<TapoException> { cam.gotoPreset("99") }.code)

        cam.alarm(true); assertEquals("start", fake.alarm)
        cam.alarm(false); assertEquals("stop", fake.alarm)

        assertEquals(-40210, assertFailsWith<TapoException> { cam.client.call("someUnknownMethod", jo()) }.code)
        assertEquals(1, fake.loginCount, "one login for the whole scenario")

        // The camera drops the session: the client must log in again transparently.
        fake.expireSession()
        assertEquals("C210", cam.info().model)
        assertEquals(2, fake.loginCount)
    }

    @Test
    fun wrongPasswordIsReportedForEachMode() {
        for (mode in AuthMode.entries) {
            val (_, cam) = setup(mode, clientPw = "pas le bon")
            val e = assertFailsWith<TapoException>("$mode") { cam.info() }
            assertEquals(-40401, e.code, "$mode: ${e.message}")
        }
    }

    @Test
    fun nightVisionFallsBackOnOlderFirmware() {
        val (fake, cam) = setup(AuthMode.SECURE_V3)
        fake.supportsNewNightVision = false
        cam.setNightVision(TapoCamera.NightVision.DAY)
        assertEquals("off", fake.state["night_old"])
        assertEquals(TapoCamera.NightVision.AUTO, cam.nightVision())
    }

    @Test
    fun capabilityProbeIsReadOnly() {
        val (fake, cam) = setup(AuthMode.TPAP)
        val before = fake.state.toMap()
        val report = cam.probeCapabilities()
        assertTrue(report.all { it.second.startsWith("OK") }, report.toString())
        assertEquals(before, fake.state)
        assertTrue(fake.calls.none { it.startsWith("set") || it == "motorMove" })
    }

    @Test
    fun parsesOnvifProbeMatch() {
        val xml = """<SOAP-ENV:Envelope><SOAP-ENV:Body><wsdd:ProbeMatches><wsdd:ProbeMatch>
            <wsdd:Scopes>onvif://www.onvif.org/name/TP-IPC onvif://www.onvif.org/hardware/C210 onvif://www.onvif.org/Profile/Streaming</wsdd:Scopes>
            <wsdd:XAddrs>http://192.168.1.42:2020/onvif/device_service</wsdd:XAddrs></wsdd:ProbeMatch></wsdd:ProbeMatches></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
        val d = Discovery.parseOnvif("192.168.1.42", xml)
        assertEquals("TP-IPC", d.onvifName)
        assertEquals("C210", d.onvifHardware)
        assertTrue(d.looksLikeTapo)
    }
}

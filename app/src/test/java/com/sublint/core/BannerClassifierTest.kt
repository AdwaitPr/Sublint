package com.sublint.core

import com.sublint.core.classifier.BannerClassifier
import com.sublint.core.model.CuratedPorts
import com.sublint.core.model.RiskSeverity
import org.junit.Assert.*
import org.junit.Test

class BannerClassifierTest {

    private val classifier = BannerClassifier()

    @Test
    fun testFtpBannerClassification() {
        val banner = "220 (vsFTPd 3.0.3)\r\n"
        val finding = classifier.classify(21, banner)

        assertEquals(21, finding.port)
        assertEquals("FTP", finding.service)
        assertEquals(RiskSeverity.MEDIUM, finding.severity)
        assertTrue(finding.advisory.contains("Unencrypted FTP"))
        assertEquals("220 (vsFTPd 3.0.3)", finding.banner)
    }

    @Test
    fun testSshBannerClassification() {
        val banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
        val finding = classifier.classify(22, banner)

        assertEquals(22, finding.port)
        assertEquals("SSH", finding.service)
        assertEquals(RiskSeverity.INFO, finding.severity)
        assertTrue(finding.advisory.contains("SSH remote shell"))
        assertEquals("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", finding.banner)
    }

    @Test
    fun testTelnetBannerClassification() {
        val banner = "\u00FF\u00FB\u0001\u00FF\u00FB\u0003Login: "
        val finding = classifier.classify(23, banner)

        assertEquals(23, finding.port)
        assertEquals("Telnet", finding.service)
        assertEquals(RiskSeverity.HIGH, finding.severity)
        assertTrue(finding.advisory.contains("Telnet"))
    }

    @Test
    fun testHttpBannerClassificationWithTitle() {
        val banner = "HTTP/1.1 200 OK\r\nServer: micro_httpd\r\n\r\n<html><head><title>Camera Admin</title></head></html>"
        val finding = classifier.classify(80, banner)

        assertEquals(80, finding.port)
        assertEquals("HTTP", finding.service)
        assertEquals(RiskSeverity.MEDIUM, finding.severity)
        assertTrue(finding.advisory.contains("Camera Admin"))
        assertTrue(finding.advisory.contains("Unencrypted HTTP"))
    }

    @Test
    fun testSmbClassification() {
        val finding = classifier.classify(445, null)

        assertEquals(445, finding.port)
        assertEquals("SMB", finding.service)
        assertEquals(RiskSeverity.MEDIUM, finding.severity)
        assertTrue(finding.advisory.contains("SMB"))
    }

    @Test
    fun testRtspCameraClassification() {
        val banner = "RTSP/1.0 200 OK\r\nServer: Hipcam RealServer/V1.0\r\nCSeq: 1\r\n\r\n"
        val finding = classifier.classify(554, banner)

        assertEquals(554, finding.port)
        assertEquals("RTSP", finding.service)
        assertEquals(RiskSeverity.HIGH, finding.severity)
        assertTrue(finding.advisory.contains("IP Camera"))
    }

    @Test
    fun testMqttConnectAdvisoryWithoutAuthPayload() {
        // Port 1883 open with null banner (no CONNECT packet sent per G3 guardrail)
        val finding = classifier.classify(1883, null)

        assertEquals(1883, finding.port)
        assertEquals("MQTT", finding.service)
        assertEquals(RiskSeverity.HIGH, finding.severity)
        assertTrue(finding.advisory.contains("MQTT smart home broker"))
    }

    @Test
    fun testJetDirectPrinterClassification() {
        val finding = classifier.classify(9100, null)

        assertEquals(9100, finding.port)
        assertEquals("JetDirect", finding.service)
        assertEquals(RiskSeverity.MEDIUM, finding.severity)
        assertTrue(finding.advisory.contains("printer"))
    }

    @Test
    fun testSanitizesOversizedAndControlCharacters() {
        // Banner with 3000 bytes and control characters (null bytes, bell, escape)
        val rawOversized = "BannerStart" + "\u0000\u0007\u001B[31m".repeat(100) + "A".repeat(3000)
        val finding = classifier.classify(8080, rawOversized)

        assertNotNull(finding.banner)
        val sanitized = finding.banner!!

        // Must be capped at 2048 characters
        assertTrue(sanitized.length <= 2048)

        // Must not contain raw control bytes like \u0000 or \u0007
        assertFalse(sanitized.contains('\u0000'))
        assertFalse(sanitized.contains('\u0007'))
    }

    @Test
    fun testAllCuratedPortsAreCovered() {
        val ports = CuratedPorts.ALL
        assertEquals(12, ports.size)
        ports.forEach { curated ->
            val finding = classifier.classify(curated.port, null)
            assertEquals(curated.port, finding.port)
            assertNotNull(finding.advisory)
        }
    }
}

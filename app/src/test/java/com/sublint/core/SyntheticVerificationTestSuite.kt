package com.sublint.core

import com.sublint.core.classifier.BannerClassifier
import com.sublint.core.model.CuratedPorts
import com.sublint.core.model.Ipv4Address
import com.sublint.core.model.SubnetValidationResult
import com.sublint.core.scanner.SubnetHostEnumerator
import org.junit.Assert.*
import org.junit.Test
import kotlin.random.Random

class SyntheticVerificationTestSuite {

    private val enumerator = SubnetHostEnumerator()
    private val classifier = BannerClassifier()

    @Test
    fun testZeroPercentNonRfc1918LeakOnSyntheticIpRanges() {
        val nonRfc1918Inputs = listOf(
            "1.1.1.1",
            "8.8.8.8",
            "8.8.4.4",
            "142.250.190.46",
            "208.67.222.222",
            "198.51.100.5",
            "203.0.113.1",
            "100.64.0.1",
            "100.100.50.25",
            "100.127.255.254",
            "127.0.0.1",
            "127.0.0.50",
            "127.255.255.254"
        )

        for (ipStr in nonRfc1918Inputs) {
            val ip = Ipv4Address.parse(ipStr)
            for (prefix in listOf(8, 16, 22, 24, 28, 30)) {
                val result = enumerator.enumerate(ip, prefix)
                assertNotEquals(
                    "Violation: Non-RFC1918 address $ipStr with prefix $prefix was validated as VALID!",
                    SubnetValidationResult.VALID,
                    result.validation
                )
                assertTrue(
                    "Violation: Target hosts emitted for non-RFC1918 address $ipStr!",
                    result.targetHosts.isEmpty()
                )
            }
        }
    }

    @Test
    fun testZeroPercentMalformedBannerCrashesAcrossAllCuratedPorts() {
        val ports = CuratedPorts.ALL.map { it.port }
        val random = Random(42)

        // 1. Extreme boundary edge cases
        val extremeBanners = mutableListOf<String?>(
            null,
            "",
            " ",
            "\u0000",
            "\u0000".repeat(5000),
            "\r\n\r\n",
            "\u00FF".repeat(1000),
            "\u001B[2J\u001B[H\u001B[31mRED ALERT\u001B[0m",
            "A".repeat(100_000), // 100k oversized string
            "<title></title>",
            "<title>" + "A".repeat(10_000) + "</title>",
            "<TITLE>MALFORMED CAPS TITLE</TITLE>",
            "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            "\t\t\t\n\n\r\r",
            "SSH-2.0-\u0000\u0007\u0008Corrupted",
            "220 " + "\u0000".repeat(500) + " ProFTPD"
        )

        // 2. Generate 500 random binary / ASCII fuzz payloads
        for (i in 0 until 500) {
            val length = random.nextInt(0, 4096)
            val chars = CharArray(length) {
                random.nextInt(0, 65536).toChar()
            }
            extremeBanners.add(String(chars))
        }

        var crashCount = 0
        var totalProbes = 0

        for (banner in extremeBanners) {
            for (port in ports) {
                totalProbes++
                try {
                    val finding = classifier.classify(port, banner)
                    assertNotNull(finding.service)
                    assertNotNull(finding.advisory)
                    if (finding.banner != null) {
                        assertTrue(
                            "Sanitization failure: banner length ${finding.banner!!.length} exceeded 2048!",
                            finding.banner!!.length <= 2048
                        )
                        assertFalse(
                            "Sanitization failure: banner contains null byte!",
                            finding.banner!!.contains('\u0000')
                        )
                    }
                } catch (t: Throwable) {
                    crashCount++
                    t.printStackTrace()
                }
            }
        }

        assertEquals("Expected 0% crashes on synthetic banner fuzzing, got: $crashCount", 0, crashCount)
        assertTrue("Probes were executed", totalProbes > 5000)
    }
}

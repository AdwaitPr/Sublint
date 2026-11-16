package com.sublint.core

import com.sublint.core.classifier.BannerClassifier
import com.sublint.core.coordinator.LanScanCoordinator
import com.sublint.core.model.Ipv4Address
import com.sublint.core.model.ScanResult
import com.sublint.core.model.SubnetValidationResult
import com.sublint.core.network.ISocketProber
import com.sublint.core.network.ProbeResult
import com.sublint.core.scanner.SubnetHostEnumerator
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class LanScanCoordinatorTest {

    private class MockSocketProber(
        private val hostResponses: Map<Pair<Ipv4Address, Int>, ProbeResult>,
        private val discoveryResponses: Map<Ipv4Address, ProbeResult>
    ) : ISocketProber {
        val probedEndpoints = mutableListOf<Pair<Ipv4Address, Int>>()

        override suspend fun probe(host: Ipv4Address, port: Int, timeoutMs: Int): ProbeResult {
            probedEndpoints.add(host to port)
            val specific = hostResponses[host to port]
            if (specific != null) return specific
            if (port == 80) {
                val disc = discoveryResponses[host]
                if (disc != null) return disc
            }
            return ProbeResult.TimedOutOrUnreachable
        }
    }

    @Test
    fun testRejectsScanWhenUserNotAuthorized() = runBlocking {
        val coordinator = LanScanCoordinator(
            hostEnumerator = SubnetHostEnumerator(),
            classifier = BannerClassifier(),
            socketProber = MockSocketProber(emptyMap(), emptyMap())
        )

        val result = coordinator.scan(
            deviceIp = Ipv4Address.parse("192.168.1.50"),
            prefixLength = 24,
            isUserAuthorized = false
        )

        assertTrue(result is ScanResult.Unauthorized)
    }

    @Test
    fun testRejectsScanForNonRfc1918Subnet() = runBlocking {
        val coordinator = LanScanCoordinator(
            hostEnumerator = SubnetHostEnumerator(),
            classifier = BannerClassifier(),
            socketProber = MockSocketProber(emptyMap(), emptyMap())
        )

        val result = coordinator.scan(
            deviceIp = Ipv4Address.parse("8.8.8.8"),
            prefixLength = 24,
            isUserAuthorized = true
        )

        assertTrue(result is ScanResult.InvalidSubnet)
        val invalidSubnet = result as ScanResult.InvalidSubnet
        assertEquals(SubnetValidationResult.NON_RFC1918, invalidSubnet.validation)
    }

    @Test
    fun testTwoPhaseScanDiscoversLiveHostsAndProbesOnlyLiveHosts() = runBlocking {
        val host1 = Ipv4Address.parse("192.168.1.1")   // Live via open port 80
        val host5 = Ipv4Address.parse("192.168.1.5")   // Live via TCP RST on port 80
        val host50 = Ipv4Address.parse("192.168.1.50") // Self IP (excluded!)

        val hostResponses = mutableMapOf<Pair<Ipv4Address, Int>, ProbeResult>()
        // Host 1: port 80 open (Router HTTP), port 554 open (RTSP Camera)
        hostResponses[host1 to 80] = ProbeResult.Open("<title>Gateway Router</title>")
        hostResponses[host1 to 554] = ProbeResult.Open("RTSP/1.0 200 OK")

        // Host 5: TCP RST on discovery port 80, port 23 open (Telnet)
        hostResponses[host5 to 80] = ProbeResult.ClosedByReset
        hostResponses[host5 to 23] = ProbeResult.Open("Login: ")

        // All other hosts time out
        val discoveryResponses = mapOf(
            host1 to ProbeResult.Open("<title>Gateway Router</title>"),
            host5 to ProbeResult.ClosedByReset
        )

        val mockProber = MockSocketProber(hostResponses, discoveryResponses)
        val coordinator = LanScanCoordinator(
            hostEnumerator = SubnetHostEnumerator(),
            classifier = BannerClassifier(),
            socketProber = mockProber
        )

        val result = coordinator.scan(
            deviceIp = host50,
            prefixLength = 24,
            isUserAuthorized = true
        )

        assertTrue(result is ScanResult.Success)
        val success = result as ScanResult.Success

        // Exactly 2 live hosts discovered
        assertEquals(2, success.hosts.size)

        val foundIps = success.hosts.map { it.host }
        assertTrue(foundIps.contains(host1))
        assertTrue(foundIps.contains(host5))
        assertFalse(foundIps.contains(host50))

        val host1Result = success.hosts.first { it.host == host1 }
        assertEquals(listOf(80, 554).sorted(), host1Result.openPorts.sorted())
        assertEquals(2, host1Result.findings.size)

        val host5Result = success.hosts.first { it.host == host5 }
        assertEquals(listOf(23), host5Result.openPorts)
        assertEquals(1, host5Result.findings.size)
        assertEquals("Telnet", host5Result.findings[0].service)

        // Verify Phase 2 audited ONLY the 2 live hosts across 12 ports:
        // Host discovery: 253 probes on port 80.
        // Audit: 2 live hosts * 12 ports = 24 probes.
        // Total probes: 253 + 24 = 277 probes.
        // (If all 253 hosts were audited, it would be 253 * 12 = 3036 probes!)
        val auditProbes = mockProber.probedEndpoints.filter { it.second != 80 || it.first == host1 || it.first == host5 }
        // Non-discovery port probes must ONLY target host1 and host5
        val nonDiscoveryProbedHosts = mockProber.probedEndpoints
            .filter { it.second != 80 }
            .map { it.first }
            .distinct()
        assertEquals(listOf(host1, host5).sortedBy { it.stringValue }, nonDiscoveryProbedHosts.sortedBy { it.stringValue })
    }
}

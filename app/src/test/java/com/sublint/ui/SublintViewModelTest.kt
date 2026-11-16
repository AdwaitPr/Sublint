package com.sublint.ui

import com.sublint.android.WifiSubnetProvider
import com.sublint.android.WifiSubnetState
import com.sublint.core.classifier.BannerClassifier
import com.sublint.core.coordinator.LanScanCoordinator
import com.sublint.core.model.*
import com.sublint.core.network.ISocketProber
import com.sublint.core.network.ProbeResult
import com.sublint.core.scanner.SubnetHostEnumerator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class SublintViewModelTest {

    private class FakeWifiSubnetProvider(var state: WifiSubnetState) : WifiSubnetProvider {
        override fun getActiveWifiSubnet(): WifiSubnetState = state
    }

    private class FakeSocketProber(
        private val responses: Map<Pair<Ipv4Address, Int>, ProbeResult>
    ) : ISocketProber {
        override suspend fun probe(host: Ipv4Address, port: Int, timeoutMs: Int): ProbeResult {
            return responses[host to port] ?: ProbeResult.TimedOutOrUnreachable
        }
    }

    @Test
    fun testScanBlockedWhenNotAuthorized() = runBlocking {
        val provider = FakeWifiSubnetProvider(
            WifiSubnetState.Connected(Ipv4Address.parse("192.168.1.50"), 24)
        )
        val coordinator = LanScanCoordinator(
            hostEnumerator = SubnetHostEnumerator(),
            classifier = BannerClassifier(),
            socketProber = FakeSocketProber(emptyMap())
        )
        val viewModel = SublintViewModel(
            wifiSubnetProvider = provider,
            scanCoordinator = coordinator,
            ioDispatcher = Dispatchers.Unconfined
        )

        viewModel.refreshNetworkState()
        assertEquals(false, viewModel.uiState.value.isAuthorized)

        viewModel.startScan()

        assertFalse(viewModel.uiState.value.isScanning)
        assertNotNull(viewModel.uiState.value.errorMessage)
        assertTrue(viewModel.uiState.value.errorMessage!!.contains("Authorization required"))
    }

    @Test
    fun testScanBlockedWhenSubnetBlockedVpn() = runBlocking {
        val provider = FakeWifiSubnetProvider(
            WifiSubnetState.Blocked("VPN connection detected.")
        )
        val coordinator = LanScanCoordinator(
            hostEnumerator = SubnetHostEnumerator(),
            classifier = BannerClassifier(),
            socketProber = FakeSocketProber(emptyMap())
        )
        val viewModel = SublintViewModel(
            wifiSubnetProvider = provider,
            scanCoordinator = coordinator,
            ioDispatcher = Dispatchers.Unconfined
        )

        viewModel.refreshNetworkState()
        viewModel.setAuthorized(true)

        viewModel.startScan()

        assertFalse(viewModel.uiState.value.isScanning)
        assertNotNull(viewModel.uiState.value.errorMessage)
        assertTrue(viewModel.uiState.value.errorMessage!!.contains("VPN connection detected"))
    }

    @Test
    fun testSuccessfulScanStateProgression() = runBlocking {
        val host1 = Ipv4Address.parse("192.168.1.1")
        val responses = mapOf(
            (host1 to 80) to ProbeResult.Open("<title>Gateway</title>")
        )
        val provider = FakeWifiSubnetProvider(
            WifiSubnetState.Connected(Ipv4Address.parse("192.168.1.50"), 24)
        )
        val coordinator = LanScanCoordinator(
            hostEnumerator = SubnetHostEnumerator(),
            classifier = BannerClassifier(),
            socketProber = FakeSocketProber(responses)
        )
        val viewModel = SublintViewModel(
            wifiSubnetProvider = provider,
            scanCoordinator = coordinator,
            ioDispatcher = Dispatchers.Unconfined
        )

        viewModel.refreshNetworkState()
        viewModel.setAuthorized(true)

        viewModel.startScan()

        val finalState = viewModel.uiState.value
        assertFalse(finalState.isScanning)
        assertNull(finalState.errorMessage)
        assertEquals(ScanPhase.COMPLETED, finalState.progress.phase)
        assertEquals(1, finalState.hostResults.size)
        assertEquals(host1, finalState.hostResults[0].host)
    }

    @Test
    fun testCancelScanStopsActiveJob() = runBlocking {
        val provider = FakeWifiSubnetProvider(
            WifiSubnetState.Connected(Ipv4Address.parse("192.168.1.50"), 24)
        )
        val coordinator = LanScanCoordinator(
            hostEnumerator = SubnetHostEnumerator(),
            classifier = BannerClassifier(),
            socketProber = FakeSocketProber(emptyMap())
        )
        val viewModel = SublintViewModel(
            wifiSubnetProvider = provider,
            scanCoordinator = coordinator,
            ioDispatcher = Dispatchers.Unconfined
        )

        viewModel.refreshNetworkState()
        viewModel.setAuthorized(true)

        viewModel.startScan()
        viewModel.cancelScan()

        val finalState = viewModel.uiState.value
        assertFalse(finalState.isScanning)
        assertEquals(ScanPhase.CANCELLED, finalState.progress.phase)
    }

    @Test
    fun testSeverityFirstHostSorting() {
        val hostLow = HostScanResult(
            host = Ipv4Address.parse("192.168.1.10"),
            openPorts = listOf(22),
            findings = listOf(
                ScanFinding(22, "SSH", "banner", "SSH advisory", RiskSeverity.INFO)
            )
        )
        val hostHigh = HostScanResult(
            host = Ipv4Address.parse("192.168.1.20"),
            openPorts = listOf(23),
            findings = listOf(
                ScanFinding(23, "Telnet", "banner", "Telnet advisory", RiskSeverity.HIGH)
            )
        )
        val hostMedium = HostScanResult(
            host = Ipv4Address.parse("192.168.1.5"),
            openPorts = listOf(80),
            findings = listOf(
                ScanFinding(80, "HTTP", "banner", "HTTP advisory", RiskSeverity.MEDIUM)
            )
        )

        val sorted = SublintViewModel.sortHostsBySeverity(listOf(hostLow, hostHigh, hostMedium))

        assertEquals(3, sorted.size)
        assertEquals(hostHigh.host, sorted[0].host)   // HIGH
        assertEquals(hostMedium.host, sorted[1].host) // MEDIUM
        assertEquals(hostLow.host, sorted[2].host)    // INFO
    }
}

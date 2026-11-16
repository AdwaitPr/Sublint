package com.sublint.core.coordinator

import com.sublint.core.classifier.IBannerClassifier
import com.sublint.core.model.*
import com.sublint.core.network.ISocketProber
import com.sublint.core.network.ProbeResult
import com.sublint.core.scanner.ISubnetHostEnumerator
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.util.concurrent.atomic.AtomicInteger

class LanScanCoordinator(
    private val hostEnumerator: ISubnetHostEnumerator,
    private val classifier: IBannerClassifier,
    private val socketProber: ISocketProber,
    private val maxConcurrentSockets: Int = 25
) {

    suspend fun scan(
        deviceIp: Ipv4Address,
        prefixLength: Int,
        isUserAuthorized: Boolean,
        discoveryPort: Int = 80,
        onProgress: ((ScanProgress) -> Unit)? = null
    ): ScanResult = coroutineScope {
        if (!isUserAuthorized) {
            return@coroutineScope ScanResult.Unauthorized(
                "Scanning aborted: User must explicitly confirm network ownership or authorization."
            )
        }

        val enumResult = hostEnumerator.enumerate(deviceIp, prefixLength)
        if (enumResult.validation != SubnetValidationResult.VALID) {
            return@coroutineScope ScanResult.InvalidSubnet(enumResult.validation)
        }

        val targetHosts = enumResult.targetHosts
        if (targetHosts.isEmpty()) {
            return@coroutineScope ScanResult.Success(emptyList())
        }

        val semaphore = Semaphore(maxConcurrentSockets)

        // PHASE 1: Host Discovery Sweep
        val liveHosts = mutableListOf<Ipv4Address>()
        val discoveryCounter = AtomicInteger(0)

        onProgress?.invoke(
            ScanProgress(
                phase = ScanPhase.DISCOVERY_SWEEP,
                scannedHosts = 0,
                totalHosts = targetHosts.size,
                activeHostsFound = 0
            )
        )

        val discoveryJobs = targetHosts.map { host ->
            async {
                val probeResult = semaphore.withPermit {
                    socketProber.probe(host, discoveryPort)
                }
                val scanned = discoveryCounter.incrementAndGet()
                val isLive = when (probeResult) {
                    is ProbeResult.Open -> true
                    is ProbeResult.ClosedByReset -> true // TCP RST proves host is online
                    is ProbeResult.TimedOutOrUnreachable -> false
                }

                if (isLive) {
                    synchronized(liveHosts) {
                        liveHosts.add(host)
                    }
                }

                onProgress?.invoke(
                    ScanProgress(
                        phase = ScanPhase.DISCOVERY_SWEEP,
                        scannedHosts = scanned,
                        totalHosts = targetHosts.size,
                        activeHostsFound = liveHosts.size
                    )
                )
            }
        }
        discoveryJobs.awaitAll()

        if (liveHosts.isEmpty()) {
            onProgress?.invoke(
                ScanProgress(
                    phase = ScanPhase.COMPLETED,
                    scannedHosts = targetHosts.size,
                    totalHosts = targetHosts.size,
                    activeHostsFound = 0
                )
            )
            return@coroutineScope ScanResult.Success(emptyList())
        }

        // PHASE 2: Port Audit on Discovered Live Hosts Only
        onProgress?.invoke(
            ScanProgress(
                phase = ScanPhase.PORT_AUDIT,
                scannedHosts = 0,
                totalHosts = liveHosts.size,
                activeHostsFound = liveHosts.size
            )
        )

        val auditedCounter = AtomicInteger(0)
        val hostAuditJobs = liveHosts.map { host ->
            async {
                val openPorts = mutableListOf<Int>()
                val findings = mutableListOf<ScanFinding>()

                // Probe all 12 curated ports on this live host
                for (curated in CuratedPorts.ALL) {
                    val result = semaphore.withPermit {
                        socketProber.probe(host, curated.port)
                    }
                    if (result is ProbeResult.Open) {
                        openPorts.add(curated.port)
                        val finding = classifier.classify(curated.port, result.banner)
                        findings.add(finding)
                    }
                }

                val completedHosts = auditedCounter.incrementAndGet()
                onProgress?.invoke(
                    ScanProgress(
                        phase = ScanPhase.PORT_AUDIT,
                        scannedHosts = completedHosts,
                        totalHosts = liveHosts.size,
                        activeHostsFound = liveHosts.size
                    )
                )

                HostScanResult(
                    host = host,
                    openPorts = openPorts,
                    findings = findings
                )
            }
        }

        val results = hostAuditJobs.awaitAll()

        onProgress?.invoke(
            ScanProgress(
                phase = ScanPhase.COMPLETED,
                scannedHosts = liveHosts.size,
                totalHosts = liveHosts.size,
                activeHostsFound = liveHosts.size
            )
        )

        ScanResult.Success(results.sortedBy { it.host })
    }
}

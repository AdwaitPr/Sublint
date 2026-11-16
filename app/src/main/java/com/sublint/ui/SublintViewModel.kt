package com.sublint.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.sublint.android.WifiSubnetProvider
import com.sublint.android.WifiSubnetState
import com.sublint.core.coordinator.LanScanCoordinator
import com.sublint.core.model.*
import com.sublint.core.scanner.ISubnetHostEnumerator
import com.sublint.core.scanner.SubnetHostEnumerator
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class SublintUiState(
    val subnetState: WifiSubnetState = WifiSubnetState.Blocked("Checking network..."),
    val targetSubnetPreview: String? = null,
    val isAuthorized: Boolean = false,
    val progress: ScanProgress = ScanProgress(ScanPhase.IDLE, 0, 0, 0),
    val isScanning: Boolean = false,
    val hostResults: List<HostScanResult> = emptyList(),
    val errorMessage: String? = null
)

class SublintViewModel(
    private val wifiSubnetProvider: WifiSubnetProvider,
    private val scanCoordinator: LanScanCoordinator,
    private val hostEnumerator: ISubnetHostEnumerator = SubnetHostEnumerator(),
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : ViewModel() {

    private val _uiState = MutableStateFlow(SublintUiState())
    val uiState: StateFlow<SublintUiState> = _uiState.asStateFlow()

    private var currentScanJob: Job? = null

    init {
        refreshNetworkState()
    }

    fun refreshNetworkState() {
        val newState = wifiSubnetProvider.getActiveWifiSubnet()
        val preview = when (newState) {
            is WifiSubnetState.Connected -> {
                val enumResult = hostEnumerator.enumerate(newState.localIp, newState.prefixLength)
                if (enumResult.validation == SubnetValidationResult.VALID) {
                    val targetCount = enumResult.targetHosts.size
                    "${newState.localIp.stringValue}/${enumResult.clampedPrefixLength} ($targetCount targetable hosts)"
                } else {
                    null
                }
            }
            is WifiSubnetState.Blocked -> null
        }

        _uiState.update {
            it.copy(
                subnetState = newState,
                targetSubnetPreview = preview,
                errorMessage = if (newState is WifiSubnetState.Blocked) newState.reason else null
            )
        }
    }

    fun setAuthorized(authorized: Boolean) {
        _uiState.update {
            it.copy(
                isAuthorized = authorized,
                errorMessage = if (authorized && it.errorMessage?.contains("Authorization") == true) null else it.errorMessage
            )
        }
    }

    fun startScan() {
        val state = _uiState.value
        if (!state.isAuthorized) {
            _uiState.update {
                it.copy(errorMessage = "Authorization required: You must confirm network ownership before scanning.")
            }
            return
        }

        val connected = state.subnetState as? WifiSubnetState.Connected
        if (connected == null) {
            val blockedReason = (state.subnetState as? WifiSubnetState.Blocked)?.reason
                ?: "Cannot scan: No valid Wi-Fi connection detected."
            _uiState.update {
                it.copy(errorMessage = blockedReason)
            }
            return
        }

        _uiState.update {
            it.copy(
                isScanning = true,
                errorMessage = null,
                hostResults = emptyList(),
                progress = ScanProgress(ScanPhase.DISCOVERY_SWEEP, 0, 0, 0)
            )
        }

        currentScanJob?.cancel()
        currentScanJob = viewModelScope.launch(ioDispatcher) {
            val result = scanCoordinator.scan(
                deviceIp = connected.localIp,
                prefixLength = connected.prefixLength,
                isUserAuthorized = true,
                onProgress = { progress ->
                    _uiState.update { it.copy(progress = progress) }
                }
            )

            when (result) {
                is ScanResult.Success -> {
                    val sorted = sortHostsBySeverity(result.hosts)
                    _uiState.update {
                        it.copy(
                            isScanning = false,
                            hostResults = sorted,
                            progress = ScanProgress(
                                phase = ScanPhase.COMPLETED,
                                scannedHosts = it.progress.totalHosts,
                                totalHosts = it.progress.totalHosts,
                                activeHostsFound = sorted.size
                            )
                        )
                    }
                }
                is ScanResult.Unauthorized -> {
                    _uiState.update {
                        it.copy(isScanning = false, errorMessage = result.reason)
                    }
                }
                is ScanResult.InvalidSubnet -> {
                    _uiState.update {
                        it.copy(isScanning = false, errorMessage = "Subnet rejected: ${result.validation}")
                    }
                }
            }
        }
    }

    fun cancelScan() {
        currentScanJob?.cancel()
        currentScanJob = null
        _uiState.update {
            it.copy(
                isScanning = false,
                progress = it.progress.copy(phase = ScanPhase.CANCELLED)
            )
        }
    }

    override fun onCleared() {
        super.onCleared()
        cancelScan()
    }

    companion object {
        fun sortHostsBySeverity(hosts: List<HostScanResult>): List<HostScanResult> {
            return hosts.sortedWith(
                compareByDescending<HostScanResult> { hostResult ->
                    hostResult.findings.maxOfOrNull { severityRank(it.severity) } ?: -1
                }.thenBy { it.host.toLong() }
            )
        }

        private fun severityRank(severity: RiskSeverity): Int = when (severity) {
            RiskSeverity.HIGH -> 3
            RiskSeverity.MEDIUM -> 2
            RiskSeverity.LOW -> 1
            RiskSeverity.INFO -> 0
        }

        fun provideFactory(
            wifiSubnetProvider: WifiSubnetProvider,
            scanCoordinator: LanScanCoordinator
        ): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                if (modelClass.isAssignableFrom(SublintViewModel::class.java)) {
                    return SublintViewModel(wifiSubnetProvider, scanCoordinator) as T
                }
                throw IllegalArgumentException("Unknown ViewModel class: ${modelClass.name}")
            }
        }
    }
}

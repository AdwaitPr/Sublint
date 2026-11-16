package com.sublint.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sublint.android.WifiSubnetState
import com.sublint.core.model.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(
    viewModel: SublintViewModel,
    modifier: Modifier = Modifier
) {
    val uiState by viewModel.uiState.collectAsState()

    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = "Sublint",
                            fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.titleLarge
                        )
                        Text(
                            text = "LAN Exposure Scanner",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                actions = {
                    IconButton(
                        onClick = { viewModel.refreshNetworkState() },
                        enabled = !uiState.isScanning
                    ) {
                        Text(
                            text = "⟳",
                            fontSize = 22.sp,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            )
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = PaddingValues(vertical = 16.dp)
        ) {
            // 1. Network Interface & Status Card
            item {
                NetworkStatusCard(
                    subnetState = uiState.subnetState,
                    targetPreview = uiState.targetSubnetPreview
                )
            }

            // 2. Authorization Confirmation Card
            item {
                AuthorizationCard(
                    isAuthorized = uiState.isAuthorized,
                    isScanning = uiState.isScanning,
                    onAuthorizationChanged = { viewModel.setAuthorized(it) }
                )
            }

            // 3. Error Banner (if any)
            if (uiState.errorMessage != null && !uiState.isScanning) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer
                        ),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = uiState.errorMessage ?: "",
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(12.dp)
                        )
                    }
                }
            }

            // 4. Scan Action Button & Progress Indicator
            item {
                ScanControlSection(
                    isScanning = uiState.isScanning,
                    canScan = uiState.isAuthorized && uiState.subnetState is WifiSubnetState.Connected,
                    progress = uiState.progress,
                    onStartScan = { viewModel.startScan() },
                    onCancelScan = { viewModel.cancelScan() }
                )
            }

            // 5. Findings Header
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Discovered Hosts & Services",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    if (uiState.hostResults.isNotEmpty()) {
                        Text(
                            text = "${uiState.hostResults.size} live host(s)",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }

            // 6. Host Results List
            if (uiState.hostResults.isEmpty() && !uiState.isScanning) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surface
                        ),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 16.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(24.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "No scan results yet. Confirm authorization and start a scan to audit your LAN.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            } else {
                items(uiState.hostResults, key = { it.host.stringValue }) { hostResult ->
                    HostResultCard(hostResult = hostResult)
                }
            }
        }
    }
}

@Composable
fun NetworkStatusCard(
    subnetState: WifiSubnetState,
    targetPreview: String?
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when (subnetState) {
                is WifiSubnetState.Connected -> MaterialTheme.colorScheme.secondaryContainer
                is WifiSubnetState.Blocked -> MaterialTheme.colorScheme.errorContainer
            }
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Wi-Fi Interface Status",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = when (subnetState) {
                    is WifiSubnetState.Connected -> MaterialTheme.colorScheme.onSecondaryContainer
                    is WifiSubnetState.Blocked -> MaterialTheme.colorScheme.onErrorContainer
                }
            )
            Spacer(modifier = Modifier.height(4.dp))
            when (subnetState) {
                is WifiSubnetState.Connected -> {
                    Text(
                        text = "Device IP: ${subnetState.localIp.stringValue}",
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium
                    )
                    if (targetPreview != null) {
                        Text(
                            text = "Target Scope: $targetPreview",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.8f)
                        )
                    }
                }
                is WifiSubnetState.Blocked -> {
                    Text(
                        text = subnetState.reason,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }
        }
    }
}

@Composable
fun AuthorizationCard(
    isAuthorized: Boolean,
    isScanning: Boolean,
    onAuthorizationChanged: (Boolean) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
                Text(
                    text = "Authorization Gate",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "I own or am explicitly authorized to audit this local network.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(
                checked = isAuthorized,
                onCheckedChange = onAuthorizationChanged,
                enabled = !isScanning
            )
        }
    }
}

@Composable
fun ScanControlSection(
    isScanning: Boolean,
    canScan: Boolean,
    progress: ScanProgress,
    onStartScan: () -> Unit,
    onCancelScan: () -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Button(
            onClick = {
                if (isScanning) onCancelScan() else onStartScan()
            },
            enabled = isScanning || canScan,
            colors = ButtonDefaults.buttonColors(
                containerColor = if (isScanning) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
            ),
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp)
        ) {
            Text(
                text = if (isScanning) "Stop Scan" else "Scan Local Subnet",
                fontWeight = FontWeight.Bold
            )
        }

        AnimatedVisibility(visible = isScanning) {
            Column(modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) {
                val fraction = if (progress.totalHosts > 0) {
                    progress.scannedHosts.toFloat() / progress.totalHosts.toFloat()
                } else 0f

                LinearProgressIndicator(
                    progress = { fraction },
                    modifier = Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(4.dp))
                )
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    val phaseName = when (progress.phase) {
                        ScanPhase.DISCOVERY_SWEEP -> "Phase 1: Host Discovery"
                        ScanPhase.PORT_AUDIT -> "Phase 2: Port & Banner Audit"
                        ScanPhase.COMPLETED -> "Completed"
                        ScanPhase.CANCELLED -> "Cancelled"
                        ScanPhase.IDLE -> "Idle"
                    }
                    Text(text = phaseName, style = MaterialTheme.typography.labelSmall)
                    Text(
                        text = "${progress.scannedHosts}/${progress.totalHosts} (${progress.activeHostsFound} alive)",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}

@Composable
fun HostResultCard(hostResult: HostScanResult) {
    var expanded by remember { mutableStateOf(false) }

    val highestSeverity = hostResult.findings.maxOfOrNull { it.severity } ?: RiskSeverity.INFO
    val badgeColor = when (highestSeverity) {
        RiskSeverity.HIGH -> MaterialTheme.colorScheme.errorContainer
        RiskSeverity.MEDIUM -> MaterialTheme.colorScheme.tertiaryContainer
        RiskSeverity.LOW -> MaterialTheme.colorScheme.secondaryContainer
        RiskSeverity.INFO -> MaterialTheme.colorScheme.primaryContainer
    }
    val badgeTextColor = when (highestSeverity) {
        RiskSeverity.HIGH -> MaterialTheme.colorScheme.onErrorContainer
        RiskSeverity.MEDIUM -> MaterialTheme.colorScheme.onTertiaryContainer
        RiskSeverity.LOW -> MaterialTheme.colorScheme.onSecondaryContainer
        RiskSeverity.INFO -> MaterialTheme.colorScheme.onPrimaryContainer
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .animateContentSize()
            .clickable { expanded = !expanded },
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = hostResult.host.stringValue,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = "${hostResult.openPorts.size} open port(s)",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                Surface(
                    color = badgeColor,
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Text(
                        text = highestSeverity.name,
                        color = badgeTextColor,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
            }

            // Port Badges
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                hostResult.openPorts.take(6).forEach { port ->
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        shape = RoundedCornerShape(6.dp)
                    ) {
                        Text(
                            text = ":$port",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                }
                if (hostResult.openPorts.size > 6) {
                    Text(
                        text = "+${hostResult.openPorts.size - 6} more",
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.align(Alignment.CenterVertically)
                    )
                }
            }

            // Expandable details (Findings & advisories)
            if (expanded) {
                Spacer(modifier = Modifier.height(12.dp))
                HorizontalDivider()
                Spacer(modifier = Modifier.height(8.dp))

                if (hostResult.findings.isEmpty()) {
                    Text(
                        text = "No risky service signatures flagged on standard ports.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    hostResult.findings.forEach { finding ->
                        FindingItemView(finding = finding)
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                }
            }
        }
    }
}

@Composable
fun FindingItemView(finding: ScanFinding) {
    val severityColor = when (finding.severity) {
        RiskSeverity.HIGH -> MaterialTheme.colorScheme.error
        RiskSeverity.MEDIUM -> MaterialTheme.colorScheme.tertiary
        RiskSeverity.LOW -> MaterialTheme.colorScheme.secondary
        RiskSeverity.INFO -> MaterialTheme.colorScheme.primary
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
            .padding(10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Port ${finding.port} • ${finding.service}",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = severityColor
            )
            Text(
                text = finding.severity.name,
                style = MaterialTheme.typography.labelSmall,
                color = severityColor,
                fontWeight = FontWeight.SemiBold
            )
        }

        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = finding.advisory,
            style = MaterialTheme.typography.bodySmall
        )

        if (!finding.banner.isNullOrBlank()) {
            Spacer(modifier = Modifier.height(4.dp))
            Surface(
                color = MaterialTheme.colorScheme.surface,
                shape = RoundedCornerShape(4.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = finding.banner,
                    style = MaterialTheme.typography.labelSmall.copy(fontSize = 11.sp),
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.padding(6.dp),
                    maxLines = 3
                )
            }
        }
    }
}

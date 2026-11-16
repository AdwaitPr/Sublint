package com.sublint.core.model

enum class SubnetValidationResult {
    VALID,
    NON_RFC1918,
    LOOPBACK,
    CARRIER_CGNAT,
    INVALID_PREFIX
}

data class SubnetEnumerationResult(
    val validation: SubnetValidationResult,
    val clampedPrefixLength: Int,
    val targetHosts: List<Ipv4Address>
)

enum class RiskSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH
}

data class CuratedPort(
    val port: Int,
    val serviceName: String,
    val defaultSeverity: RiskSeverity,
    val description: String
)

object CuratedPorts {
    val PORT_21_FTP = CuratedPort(21, "FTP", RiskSeverity.MEDIUM, "Cleartext File Transfer Protocol")
    val PORT_22_SSH = CuratedPort(22, "SSH", RiskSeverity.INFO, "Secure Shell remote management")
    val PORT_23_TELNET = CuratedPort(23, "Telnet", RiskSeverity.HIGH, "Legacy cleartext remote terminal")
    val PORT_80_HTTP = CuratedPort(80, "HTTP", RiskSeverity.MEDIUM, "Unencrypted web management console")
    val PORT_445_SMB = CuratedPort(445, "SMB", RiskSeverity.MEDIUM, "Windows / Samba network file sharing")
    val PORT_554_RTSP = CuratedPort(554, "RTSP", RiskSeverity.HIGH, "Real-Time Streaming Protocol (IP camera)")
    val PORT_1883_MQTT = CuratedPort(1883, "MQTT", RiskSeverity.HIGH, "Smart home / IoT telemetry broker")
    val PORT_3389_RDP = CuratedPort(3389, "RDP", RiskSeverity.MEDIUM, "Windows Remote Desktop Protocol")
    val PORT_5000_NAS = CuratedPort(5000, "NAS-Admin", RiskSeverity.MEDIUM, "Synology / NAS / UPnP management portal")
    val PORT_8080_HTTP_ALT = CuratedPort(8080, "HTTP-Alt", RiskSeverity.MEDIUM, "Alternative web management portal")
    val PORT_8443_HTTPS_ALT = CuratedPort(8443, "HTTPS-Alt", RiskSeverity.INFO, "Alternative secure web admin portal")
    val PORT_9100_JETDIRECT = CuratedPort(9100, "JetDirect", RiskSeverity.MEDIUM, "Raw network printer interface")

    val ALL: List<CuratedPort> = listOf(
        PORT_21_FTP,
        PORT_22_SSH,
        PORT_23_TELNET,
        PORT_80_HTTP,
        PORT_445_SMB,
        PORT_554_RTSP,
        PORT_1883_MQTT,
        PORT_3389_RDP,
        PORT_5000_NAS,
        PORT_8080_HTTP_ALT,
        PORT_8443_HTTPS_ALT,
        PORT_9100_JETDIRECT
    )

    fun find(port: Int): CuratedPort? = ALL.firstOrNull { it.port == port }
}

data class ScanFinding(
    val port: Int,
    val service: String,
    val banner: String?,
    val advisory: String,
    val severity: RiskSeverity
)

data class HostScanResult(
    val host: Ipv4Address,
    val openPorts: List<Int>,
    val findings: List<ScanFinding>
)

enum class ScanPhase {
    IDLE,
    DISCOVERY_SWEEP,
    PORT_AUDIT,
    COMPLETED,
    CANCELLED
}

data class ScanProgress(
    val phase: ScanPhase,
    val scannedHosts: Int,
    val totalHosts: Int,
    val activeHostsFound: Int
)

sealed interface ScanResult {
    data class Success(val hosts: List<HostScanResult>) : ScanResult
    data class Unauthorized(val reason: String) : ScanResult
    data class InvalidSubnet(val validation: SubnetValidationResult) : ScanResult
}

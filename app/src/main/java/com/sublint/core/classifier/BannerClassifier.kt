package com.sublint.core.classifier

import com.sublint.core.model.CuratedPorts
import com.sublint.core.model.RiskSeverity
import com.sublint.core.model.ScanFinding

interface IBannerClassifier {
    fun classify(port: Int, rawBanner: String?): ScanFinding
    fun sanitizeBanner(raw: String?): String?
}

class BannerClassifier : IBannerClassifier {

    override fun sanitizeBanner(raw: String?): String? {
        if (raw == null) return null
        val trimmed = raw.take(MAX_BANNER_LENGTH)
        val sb = StringBuilder(trimmed.length)
        for (ch in trimmed) {
            when {
                ch == '\n' || ch == '\r' || ch == '\t' -> sb.append(ch)
                ch.code in 32..126 -> sb.append(ch)
                // Filter out non-printable ASCII control characters (0..31 and 127)
                ch.code < 32 || ch.code == 127 -> { /* omit control character */ }
                else -> sb.append(ch)
            }
        }
        val clean = sb.toString().trim()
        return if (clean.isEmpty()) null else clean
    }

    override fun classify(port: Int, rawBanner: String?): ScanFinding {
        val banner = sanitizeBanner(rawBanner)
        val curated = CuratedPorts.find(port)

        return when (port) {
            21 -> classifyFtp(banner, curated?.defaultSeverity ?: RiskSeverity.MEDIUM)
            22 -> classifySsh(banner, curated?.defaultSeverity ?: RiskSeverity.INFO)
            23 -> classifyTelnet(banner, curated?.defaultSeverity ?: RiskSeverity.HIGH)
            80 -> classifyHttp(80, banner, curated?.defaultSeverity ?: RiskSeverity.MEDIUM)
            445 -> classifySmb(curated?.defaultSeverity ?: RiskSeverity.MEDIUM)
            554 -> classifyRtsp(banner, curated?.defaultSeverity ?: RiskSeverity.HIGH)
            1883 -> classifyMqtt(curated?.defaultSeverity ?: RiskSeverity.HIGH)
            3389 -> classifyRdp(curated?.defaultSeverity ?: RiskSeverity.MEDIUM)
            5000 -> classifyNas(banner, curated?.defaultSeverity ?: RiskSeverity.MEDIUM)
            8080 -> classifyHttp(8080, banner, curated?.defaultSeverity ?: RiskSeverity.MEDIUM)
            8443 -> classifyHttpsAlt(banner, curated?.defaultSeverity ?: RiskSeverity.INFO)
            9100 -> classifyJetDirect(curated?.defaultSeverity ?: RiskSeverity.MEDIUM)
            else -> ScanFinding(
                port = port,
                service = curated?.serviceName ?: "Port-$port",
                banner = banner,
                advisory = "Service detected open on port $port.",
                severity = curated?.defaultSeverity ?: RiskSeverity.LOW
            )
        }
    }

    private fun classifyFtp(banner: String?, defaultSeverity: RiskSeverity): ScanFinding {
        val advisory = "Unencrypted FTP server active. Transmits credentials and files in cleartext across the local network."
        return ScanFinding(21, "FTP", banner, advisory, defaultSeverity)
    }

    private fun classifySsh(banner: String?, defaultSeverity: RiskSeverity): ScanFinding {
        val advisory = "SSH remote shell service exposed. Ensure password authentication is hardened or key-only."
        return ScanFinding(22, "SSH", banner, advisory, defaultSeverity)
    }

    private fun classifyTelnet(banner: String?, defaultSeverity: RiskSeverity): ScanFinding {
        val advisory = "Legacy cleartext Telnet service active. High risk of default credentials and sniffing. Recommend disabling."
        return ScanFinding(23, "Telnet", banner, advisory, defaultSeverity)
    }

    private fun classifyHttp(port: Int, banner: String?, defaultSeverity: RiskSeverity): ScanFinding {
        val service = if (port == 80) "HTTP" else "HTTP-Alt"
        val title = extractHtmlTitle(banner)
        val titleSnippet = if (title != null) " (Title: '$title')" else ""
        val advisory = "Unencrypted HTTP web management console exposed without TLS$titleSnippet. Verify strong admin credentials."
        return ScanFinding(port, service, banner, advisory, defaultSeverity)
    }

    private fun classifySmb(defaultSeverity: RiskSeverity): ScanFinding {
        val advisory = "Exposed SMB file sharing service. Network file shares accessible to devices on this subnet."
        return ScanFinding(445, "SMB", null, advisory, defaultSeverity)
    }

    private fun classifyRtsp(banner: String?, defaultSeverity: RiskSeverity): ScanFinding {
        val advisory = "Exposed RTSP IP Camera video stream. Video stream endpoint may be unauthenticated on local network."
        return ScanFinding(554, "RTSP", banner, advisory, defaultSeverity)
    }

    private fun classifyMqtt(defaultSeverity: RiskSeverity): ScanFinding {
        val advisory = "Exposed MQTT smart home broker. Telemetry and home automation controls may accept unauthenticated connections."
        return ScanFinding(1883, "MQTT", null, advisory, defaultSeverity)
    }

    private fun classifyRdp(defaultSeverity: RiskSeverity): ScanFinding {
        val advisory = "Exposed Windows Remote Desktop (RDP) service. Ensure Network Level Authentication (NLA) is required."
        return ScanFinding(3389, "RDP", null, advisory, defaultSeverity)
    }

    private fun classifyNas(banner: String?, defaultSeverity: RiskSeverity): ScanFinding {
        val title = extractHtmlTitle(banner)
        val titleSnippet = if (title != null) " (Title: '$title')" else ""
        val advisory = "Exposed NAS or storage management dashboard on port 5000$titleSnippet."
        return ScanFinding(5000, "NAS-Admin", banner, advisory, defaultSeverity)
    }

    private fun classifyHttpsAlt(banner: String?, defaultSeverity: RiskSeverity): ScanFinding {
        val advisory = "Exposed HTTPS administration portal. Encrypted web UI active."
        return ScanFinding(8443, "HTTPS-Alt", banner, advisory, defaultSeverity)
    }

    private fun classifyJetDirect(defaultSeverity: RiskSeverity): ScanFinding {
        val advisory = "Exposed RAW JetDirect network printer port (9100). Unauthenticated print jobs can be submitted by local hosts."
        return ScanFinding(9100, "JetDirect", null, advisory, defaultSeverity)
    }

    private fun extractHtmlTitle(html: String?): String? {
        if (html == null) return null
        val lower = html.lowercase()
        val startTag = "<title>"
        val endTag = "</title>"
        val startIndex = lower.indexOf(startTag)
        if (startIndex == -1) return null
        val endIndex = lower.indexOf(endTag, startIndex + startTag.length)
        if (endIndex == -1) return null
        val rawTitle = html.substring(startIndex + startTag.length, endIndex).trim()
        return rawTitle.take(64)
    }

    companion object {
        const val MAX_BANNER_LENGTH = 2048
    }
}

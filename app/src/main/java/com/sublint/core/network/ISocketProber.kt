package com.sublint.core.network

import com.sublint.core.model.Ipv4Address

sealed interface ProbeResult {
    data class Open(val banner: String? = null) : ProbeResult
    object ClosedByReset : ProbeResult          // TCP RST packet received (host is active)
    object TimedOutOrUnreachable : ProbeResult  // Host down or dropped by firewall
}

interface ISocketProber {
    suspend fun probe(host: Ipv4Address, port: Int, timeoutMs: Int = 400): ProbeResult
}

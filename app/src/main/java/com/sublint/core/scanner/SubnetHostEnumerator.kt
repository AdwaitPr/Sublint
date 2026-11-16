package com.sublint.core.scanner

import com.sublint.core.model.Ipv4Address
import com.sublint.core.model.SubnetEnumerationResult
import com.sublint.core.model.SubnetValidationResult

interface ISubnetHostEnumerator {
    fun enumerate(deviceIp: Ipv4Address, prefixLength: Int): SubnetEnumerationResult
}

class SubnetHostEnumerator : ISubnetHostEnumerator {

    override fun enumerate(deviceIp: Ipv4Address, prefixLength: Int): SubnetEnumerationResult {
        if (deviceIp.isLoopback()) {
            return SubnetEnumerationResult(SubnetValidationResult.LOOPBACK, prefixLength, emptyList())
        }
        if (deviceIp.isCarrierCgnat()) {
            return SubnetEnumerationResult(SubnetValidationResult.CARRIER_CGNAT, prefixLength, emptyList())
        }
        if (!deviceIp.isRfc1918()) {
            return SubnetEnumerationResult(SubnetValidationResult.NON_RFC1918, prefixLength, emptyList())
        }
        if (prefixLength !in 1..30) {
            return SubnetEnumerationResult(SubnetValidationResult.INVALID_PREFIX, prefixLength, emptyList())
        }

        // Clamp any prefix wider than /24 (e.g. /16 or /22) strictly to the local /24 slice
        val clampedPrefix = if (prefixLength < 24) 24 else prefixLength

        val mask = (0xFFFFFFFFL shl (32 - clampedPrefix)) and 0xFFFFFFFFL
        val ipLong = deviceIp.toLong()
        val networkLong = ipLong and mask
        val broadcastLong = networkLong or (mask.inv() and 0xFFFFFFFFL)

        val targetHosts = mutableListOf<Ipv4Address>()
        for (candidateLong in (networkLong + 1) until broadcastLong) {
            val candidate = Ipv4Address.fromLong(candidateLong)
            // Exclude the scanning device's own IP
            if (candidate != deviceIp) {
                targetHosts.add(candidate)
            }
        }

        return SubnetEnumerationResult(
            validation = SubnetValidationResult.VALID,
            clampedPrefixLength = clampedPrefix,
            targetHosts = targetHosts
        )
    }
}

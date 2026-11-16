package com.sublint.core

import com.sublint.core.model.Ipv4Address
import com.sublint.core.model.SubnetValidationResult
import com.sublint.core.scanner.SubnetHostEnumerator
import org.junit.Assert.*
import org.junit.Test

class SubnetHostEnumeratorTest {

    private val enumerator = SubnetHostEnumerator()

    @Test
    fun testValidRFC1918Subnet24_GeneratesCorrectHostsExcludingSelfAndBounds() {
        val selfIp = Ipv4Address.parse("192.168.1.50")
        val result = enumerator.enumerate(selfIp, prefixLength = 24)

        assertTrue(result.validation == SubnetValidationResult.VALID)
        val hosts = result.targetHosts

        // Total usable hosts in /24 is 254 (.1 through .254) minus self (.50) = 253
        assertEquals(253, hosts.size)

        // Must not contain network (.0), broadcast (.255), or self (.50)
        assertFalse(hosts.contains(Ipv4Address.parse("192.168.1.0")))
        assertFalse(hosts.contains(Ipv4Address.parse("192.168.1.255")))
        assertFalse(hosts.contains(Ipv4Address.parse("192.168.1.50")))

        // Must contain boundary valid hosts
        assertTrue(hosts.contains(Ipv4Address.parse("192.168.1.1")))
        assertTrue(hosts.contains(Ipv4Address.parse("192.168.1.254")))
    }

    @Test
    fun testClampingLargeSubnet16_ClampsToLocal24() {
        val selfIp = Ipv4Address.parse("10.0.5.12")
        // User network is configured with /16
        val result = enumerator.enumerate(selfIp, prefixLength = 16)

        assertTrue(result.validation == SubnetValidationResult.VALID)
        assertEquals(24, result.clampedPrefixLength)
        val hosts = result.targetHosts

        // Clamped strictly to 10.0.5.0/24
        assertEquals(253, hosts.size)
        assertFalse(hosts.contains(Ipv4Address.parse("10.0.5.12")))
        assertFalse(hosts.contains(Ipv4Address.parse("10.0.5.0")))
        assertFalse(hosts.contains(Ipv4Address.parse("10.0.5.255")))
        assertTrue(hosts.all { it.octets[0] == 10 && it.octets[1] == 0 && it.octets[2] == 5 })
    }

    @Test
    fun testSmallSubnet28_GeneratesCorrectHosts() {
        // 172.16.10.18/28 -> Subnet is 172.16.10.16 to 172.16.10.31
        val selfIp = Ipv4Address.parse("172.16.10.18")
        val result = enumerator.enumerate(selfIp, prefixLength = 28)

        assertTrue(result.validation == SubnetValidationResult.VALID)
        val hosts = result.targetHosts

        // 16 total addresses - network (.16) - broadcast (.31) - self (.18) = 13 hosts
        assertEquals(13, hosts.size)
        assertFalse(hosts.contains(Ipv4Address.parse("172.16.10.16")))
        assertFalse(hosts.contains(Ipv4Address.parse("172.16.10.31")))
        assertFalse(hosts.contains(Ipv4Address.parse("172.16.10.18")))
        assertTrue(hosts.contains(Ipv4Address.parse("172.16.10.17")))
        assertTrue(hosts.contains(Ipv4Address.parse("172.16.10.30")))
    }

    @Test
    fun testRejectPublicIpAddress() {
        val publicIp = Ipv4Address.parse("8.8.8.8")
        val result = enumerator.enumerate(publicIp, prefixLength = 24)

        assertEquals(SubnetValidationResult.NON_RFC1918, result.validation)
        assertTrue(result.targetHosts.isEmpty())
    }

    @Test
    fun testRejectLoopbackAddress() {
        val loopback = Ipv4Address.parse("127.0.0.1")
        val result = enumerator.enumerate(loopback, prefixLength = 8)

        assertEquals(SubnetValidationResult.LOOPBACK, result.validation)
        assertTrue(result.targetHosts.isEmpty())
    }

    @Test
    fun testRejectCarrierCgnatAddress() {
        val cgnat = Ipv4Address.parse("100.64.0.1")
        val result = enumerator.enumerate(cgnat, prefixLength = 24)

        assertEquals(SubnetValidationResult.CARRIER_CGNAT, result.validation)
        assertTrue(result.targetHosts.isEmpty())
    }
}

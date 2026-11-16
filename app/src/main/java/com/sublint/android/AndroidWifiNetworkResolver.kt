package com.sublint.android

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.sublint.core.model.Ipv4Address
import java.net.Inet4Address

sealed interface WifiSubnetState {
    data class Connected(val localIp: Ipv4Address, val prefixLength: Int) : WifiSubnetState
    data class Blocked(val reason: String) : WifiSubnetState
}

interface WifiSubnetProvider {
    fun getActiveWifiSubnet(): WifiSubnetState
}

class AndroidWifiNetworkResolver(
    private val connectivityManager: ConnectivityManager
) : WifiSubnetProvider {

    override fun getActiveWifiSubnet(): WifiSubnetState {
        val activeNetwork = connectivityManager.activeNetwork
            ?: return WifiSubnetState.Blocked("No active network connection detected.")

        val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
            ?: return WifiSubnetState.Blocked("Unable to query active network capabilities.")

        // Enforce Wi-Fi transport
        if (!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            return WifiSubnetState.Blocked(
                "Active network is not Wi-Fi. Sublint requires a direct local Wi-Fi connection."
            )
        }

        // Hard-block VPN interfaces to prevent scanning remote corporate networks
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            return WifiSubnetState.Blocked(
                "VPN tunnel is active. Sublint blocks scanning while connected to a VPN to protect private remote subnets."
            )
        }

        // Hard-block cellular connections
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
            return WifiSubnetState.Blocked(
                "Cellular carrier transport detected. Scanning over mobile networks is forbidden."
            )
        }

        val linkProperties = connectivityManager.getLinkProperties(activeNetwork)
            ?: return WifiSubnetState.Blocked("Unable to read Wi-Fi network link properties.")

        for (linkAddress in linkProperties.linkAddresses) {
            val address = linkAddress.address
            if (address is Inet4Address && !address.isLoopbackAddress && !address.isLinkLocalAddress) {
                val octets = address.address.map { it.toInt() and 0xFF }
                val localIp = Ipv4Address(octets)
                val prefixLength = linkAddress.prefixLength
                return WifiSubnetState.Connected(localIp, prefixLength)
            }
        }

        return WifiSubnetState.Blocked("No valid IPv4 address found on active Wi-Fi interface.")
    }
}

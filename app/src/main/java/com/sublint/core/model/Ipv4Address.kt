package com.sublint.core.model

data class Ipv4Address(val octets: List<Int>) : Comparable<Ipv4Address> {
    init {
        require(octets.size == 4) { "IPv4 address must contain exactly 4 octets, got: ${octets.size}" }
        require(octets.all { it in 0..255 }) { "IPv4 octets must be in 0..255, got: $octets" }
    }

    val stringValue: String get() = octets.joinToString(".")

    fun toLong(): Long {
        return (octets[0].toLong() shl 24) or
                (octets[1].toLong() shl 16) or
                (octets[2].toLong() shl 8) or
                octets[3].toLong()
    }

    fun isRfc1918(): Boolean {
        val (o1, o2) = octets[0] to octets[1]
        return (o1 == 10) ||
                (o1 == 172 && o2 in 16..31) ||
                (o1 == 192 && o2 == 168)
    }

    fun isLoopback(): Boolean = octets[0] == 127

    fun isCarrierCgnat(): Boolean = octets[0] == 100 && octets[1] in 64..127

    override fun compareTo(other: Ipv4Address): Int = toLong().compareTo(other.toLong())

    override fun toString(): String = stringValue

    companion object {
        fun parse(ipString: String): Ipv4Address {
            val parts = ipString.trim().split(".")
            require(parts.size == 4) { "Invalid IPv4 format: $ipString" }
            val octets = parts.map {
                val value = it.toIntOrNull() ?: throw IllegalArgumentException("Non-integer octet in: $ipString")
                require(value in 0..255) { "Octet out of range 0..255 in: $ipString" }
                value
            }
            return Ipv4Address(octets)
        }

        fun fromLong(value: Long): Ipv4Address {
            val o1 = ((value shr 24) and 0xFF).toInt()
            val o2 = ((value shr 16) and 0xFF).toInt()
            val o3 = ((value shr 8) and 0xFF).toInt()
            val o4 = (value and 0xFF).toInt()
            return Ipv4Address(listOf(o1, o2, o3, o4))
        }
    }
}

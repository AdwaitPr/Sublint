package com.sublint.core.network

import com.sublint.core.model.Ipv4Address
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class JavaSocketProber(
    private val defaultConnectTimeoutMs: Int = 400,
    private val readTimeoutMs: Int = 250
) : ISocketProber {

    override suspend fun probe(host: Ipv4Address, port: Int, timeoutMs: Int): ProbeResult {
        return probeInternal(host, port, timeoutMs, serverPortOverride = null)
    }

    suspend fun probe(
        host: Ipv4Address,
        port: Int,
        timeoutMs: Int = defaultConnectTimeoutMs,
        serverPortOverride: Int? = null
    ): ProbeResult {
        return probeInternal(host, port, timeoutMs, serverPortOverride)
    }

    private suspend fun probeInternal(
        host: Ipv4Address,
        port: Int,
        timeoutMs: Int,
        serverPortOverride: Int?
    ): ProbeResult = withContext(Dispatchers.IO) {
        val targetPort = serverPortOverride ?: port
        val socket = Socket()

        try {
            socket.tcpNoDelay = true
            socket.setSoLinger(true, 0)
            val endpoint = InetSocketAddress(host.stringValue, targetPort)
            socket.connect(endpoint, timeoutMs)
        } catch (e: ConnectException) {
            try { socket.close() } catch (_: Throwable) {}
            return@withContext ProbeResult.ClosedByReset
        } catch (e: SocketTimeoutException) {
            try { socket.close() } catch (_: Throwable) {}
            return@withContext ProbeResult.TimedOutOrUnreachable
        } catch (e: IOException) {
            try { socket.close() } catch (_: Throwable) {}
            return@withContext ProbeResult.TimedOutOrUnreachable
        } catch (e: Throwable) {
            try { socket.close() } catch (_: Throwable) {}
            return@withContext ProbeResult.TimedOutOrUnreachable
        }

        // Port is open (TCP connection established).
        try {
            socket.soTimeout = readTimeoutMs
            val banner = readBannerForPort(socket, host, port, targetPort)
            ProbeResult.Open(banner)
        } catch (e: Throwable) {
            // If reading the banner fails or times out, the port is still verified OPEN.
            ProbeResult.Open(banner = null)
        } finally {
            try {
                socket.close()
            } catch (_: Throwable) {}
        }
    }

    private fun readBannerForPort(
        socket: Socket,
        host: Ipv4Address,
        servicePort: Int,
        targetPort: Int
    ): String? {
        return when (servicePort) {
            // Immediate return upon connection for non-banner / connect-only ports
            445, 1883, 3389, 9100 -> null

            // Direct server greeting banner ports
            21, 22, 23 -> readDirectBanner(socket)

            // Web management admin console ports
            80, 5000, 8080 -> {
                val request = "GET / HTTP/1.0\r\nHost: ${host.stringValue}\r\nConnection: close\r\n\r\n"
                sendAndRead(socket, request)
            }

            // RTSP streaming camera port
            554 -> {
                val request = "OPTIONS rtsp://${host.stringValue}:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                sendAndRead(socket, request)
            }

            // Secure admin portal port
            8443 -> inspectSslSubject(socket, host, targetPort)

            else -> null
        }
    }

    private fun readDirectBanner(socket: Socket): String? {
        val buffer = ByteArray(MAX_BANNER_BYTES)
        val bytesRead = socket.getInputStream().read(buffer)
        return if (bytesRead > 0) String(buffer, 0, bytesRead, Charsets.UTF_8) else null
    }

    private fun sendAndRead(socket: Socket, payload: String): String? {
        val out = socket.getOutputStream()
        out.write(payload.toByteArray(Charsets.US_ASCII))
        out.flush()
        val buffer = ByteArray(MAX_BANNER_BYTES)
        val bytesRead = socket.getInputStream().read(buffer)
        return if (bytesRead > 0) String(buffer, 0, bytesRead, Charsets.UTF_8) else null
    }

    private fun inspectSslSubject(socket: Socket, host: Ipv4Address, port: Int): String? {
        val sslContext = SSLContext.getInstance("TLS")
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        sslContext.init(null, trustAll, SecureRandom())
        val sslSocket = sslContext.socketFactory.createSocket(socket, host.stringValue, port, true) as SSLSocket
        sslSocket.soTimeout = readTimeoutMs
        sslSocket.startHandshake()
        val certs = sslSocket.session.peerCertificates
        val x509 = certs.firstOrNull() as? X509Certificate
        return x509?.subjectX500Principal?.name
    }

    companion object {
        const val MAX_BANNER_BYTES = 2048
    }
}

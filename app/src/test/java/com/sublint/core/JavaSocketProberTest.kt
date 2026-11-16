package com.sublint.core

import com.sublint.core.model.Ipv4Address
import com.sublint.core.network.JavaSocketProber
import com.sublint.core.network.ProbeResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread

class JavaSocketProberTest {

    private val localHost = Ipv4Address.parse("127.0.0.1")

    @Test
    fun testFtpBannerRead() = runBlocking {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = server.localPort

        val serverThread = thread {
            try {
                val client = server.accept()
                client.getOutputStream().write("220 ProFTPD 1.3.5 Server ready.\r\n".toByteArray(Charsets.US_ASCII))
                client.getOutputStream().flush()
                client.close()
            } catch (_: Exception) {}
        }

        val prober = JavaSocketProber(defaultConnectTimeoutMs = 500, readTimeoutMs = 500)
        val result = prober.probe(localHost, 21, serverPortOverride = port)

        serverThread.join(1000)
        server.close()

        assertTrue(result is ProbeResult.Open)
        val openResult = result as ProbeResult.Open
        assertNotNull(openResult.banner)
        assertTrue(openResult.banner!!.contains("220 ProFTPD 1.3.5 Server ready."))
    }

    @Test
    fun testHttpTitleAndHeaderExtraction() = runBlocking {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = server.localPort

        val serverThread = thread {
            try {
                val client = server.accept()
                val reader = BufferedReader(InputStreamReader(client.getInputStream(), Charsets.US_ASCII))
                val firstLine = reader.readLine()
                assertTrue("Expected HTTP GET request, got: $firstLine", firstLine.startsWith("GET / HTTP/1.0"))

                val response = "HTTP/1.0 200 OK\r\nServer: Lighttpd/1.4\r\nContent-Type: text/html\r\n\r\n<html><head><title>Router Gateway</title></head></html>"
                client.getOutputStream().write(response.toByteArray(Charsets.US_ASCII))
                client.getOutputStream().flush()
                client.close()
            } catch (_: Exception) {}
        }

        val prober = JavaSocketProber(defaultConnectTimeoutMs = 500, readTimeoutMs = 500)
        val result = prober.probe(localHost, 80, serverPortOverride = port)

        serverThread.join(1000)
        server.close()

        assertTrue(result is ProbeResult.Open)
        val openResult = result as ProbeResult.Open
        assertNotNull(openResult.banner)
        assertTrue(openResult.banner!!.contains("Router Gateway"))
        assertTrue(openResult.banner!!.contains("Lighttpd/1.4"))
    }

    @Test
    fun testConnectOnlyPortImmediateReturn() = runBlocking {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = server.localPort

        val serverThread = thread {
            try {
                val client = server.accept()
                // Keep connected without writing anything
                Thread.sleep(100)
                client.close()
            } catch (_: Exception) {}
        }

        val prober = JavaSocketProber(defaultConnectTimeoutMs = 500, readTimeoutMs = 250)
        // Port 445 is configured as connect-only (immediate return without waiting on read)
        val result = prober.probe(localHost, 445, serverPortOverride = port)

        serverThread.join(1000)
        server.close()

        assertTrue(result is ProbeResult.Open)
        val openResult = result as ProbeResult.Open
        // Connect-only port returns banner = null immediately
        assertNull(openResult.banner)
    }

    @Test
    fun testClosedPortReturnsClosedByReset() = runBlocking {
        // Open and immediately close a ServerSocket to find an unused closed port
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val closedPort = server.localPort
        server.close()

        val prober = JavaSocketProber(defaultConnectTimeoutMs = 500, readTimeoutMs = 250)
        val result = prober.probe(localHost, 80, serverPortOverride = closedPort)

        assertEquals(ProbeResult.ClosedByReset, result)
    }

    @Test
    fun testReadTimeoutCapOnSilentServer() = runBlocking {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = server.localPort

        val serverThread = thread {
            try {
                val client = server.accept()
                // Silent server: sleeps longer than readTimeoutMs
                Thread.sleep(600)
                client.close()
            } catch (_: Exception) {}
        }

        val prober = JavaSocketProber(defaultConnectTimeoutMs = 500, readTimeoutMs = 150)
        val startTime = System.currentTimeMillis()
        // Probing port 21 on a silent server
        val result = prober.probe(localHost, 21, serverPortOverride = port)
        val duration = System.currentTimeMillis() - startTime

        serverThread.join(1000)
        server.close()

        // Socket connected successfully, but read timed out after ~150ms
        assertTrue(result is ProbeResult.Open)
        val openResult = result as ProbeResult.Open
        assertNull(openResult.banner)
        // Verify timeout cap: should complete well before 1000ms
        assertTrue("Expected prompt return on read timeout, took: $duration ms", duration < 800)
    }

    @Test
    fun testRtspHeaderExtraction() = runBlocking {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = server.localPort

        val serverThread = thread {
            try {
                val client = server.accept()
                val reader = BufferedReader(InputStreamReader(client.getInputStream(), Charsets.US_ASCII))
                val firstLine = reader.readLine()
                assertTrue("Expected RTSP OPTIONS request, got: $firstLine", firstLine.startsWith("OPTIONS rtsp://"))

                val response = "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hipcam RealServer/V1.0\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"
                client.getOutputStream().write(response.toByteArray(Charsets.US_ASCII))
                client.getOutputStream().flush()
                client.close()
            } catch (_: Exception) {}
        }

        val prober = JavaSocketProber(defaultConnectTimeoutMs = 500, readTimeoutMs = 500)
        val result = prober.probe(localHost, 554, serverPortOverride = port)

        serverThread.join(1000)
        server.close()

        assertTrue(result is ProbeResult.Open)
        val openResult = result as ProbeResult.Open
        assertNotNull(openResult.banner)
        assertTrue(openResult.banner!!.contains("Hipcam RealServer/V1.0"))
    }
}

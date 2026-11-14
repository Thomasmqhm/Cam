package com.camctl.core

import java.io.File
import java.net.InetAddress
import javax.net.ssl.SSLServerSocket
import kotlin.concurrent.thread
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * End-to-end over real TLS: the simulated camera sits behind an HTTPS server with a freshly
 * generated self-signed certificate, like a real Tapo, and the production [JdkHttpPoster] talks to it.
 */
class HttpsTransportTest {
    @Test
    fun talksToSelfSignedHttpsCamera() {
        val ksFile = File.createTempFile("cam", ".p12").apply { delete(); deleteOnExit() }
        val keytool = File(System.getProperty("java.home"), "bin/keytool").path
        val p = ProcessBuilder(keytool, "-genkeypair", "-alias", "cam", "-keyalg", "EC", "-groupname", "secp256r1",
            "-dname", "CN=192.168.1.42", "-validity", "2", "-storetype", "PKCS12", "-keystore", ksFile.path, "-storepass", "changeit")
            .redirectErrorStream(true).start()
        assertEquals(0, p.waitFor(), p.inputStream.bufferedReader().readText())

        val ks = KeyStore.getInstance("PKCS12").apply { ksFile.inputStream().use { load(it, "changeit".toCharArray()) } }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, "changeit".toCharArray()) }
        val ssl = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }

        for (mode in AuthMode.entries) {
            val fake = FakeCamera(mode, "pw")
            val server = ssl.serverSocketFactory.createServerSocket(0, 50, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
            thread(isDaemon = true) {
                while (!server.isClosed) {
                    val sock = try { server.accept() } catch (_: Exception) { break }
                    sock.use { serveOne(it, fake) }
                }
            }
            try {
                val cam = TapoCamera(TapoClient("127.0.0.1", "pw", port = server.localPort, http = JdkHttpPoster()))
                assertEquals("C210", cam.info().model, "$mode")
                cam.setLed(false)
                assertEquals("off", fake.state["led"], "$mode")
                assertEquals(mode, cam.client.mode)
            } finally {
                server.close()
            }
        }
    }

    /** Minimal HTTP/1.1: one request per connection, Content-Length bodies. */
    private fun serveOne(sock: java.net.Socket, fake: FakeCamera) {
        val input = java.io.BufferedInputStream(sock.getInputStream())
        fun line(): String {
            val sb = StringBuilder()
            while (true) { val c = input.read(); if (c < 0 || c == '\n'.code) break; if (c != '\r'.code) sb.append(c.toChar()) }
            return sb.toString()
        }
        val path = line().split(" ")[1]
        val headers = LinkedHashMap<String, String>()
        while (true) {
            val l = line(); if (l.isEmpty()) break
            val k = l.substringBefore(":").trim(); val v = l.substringAfter(":").trim()
            headers[when { k.equals("seq", true) -> "Seq"; k.equals("tapo_tag", true) -> "Tapo_tag"; else -> k }] = v
        }
        val len = headers.entries.firstOrNull { it.key.equals("content-length", true) }?.value?.toInt() ?: 0
        val body = ByteArray(len); var off = 0
        while (off < len) { val n = input.read(body, off, len - off); if (n < 0) break; off += n }
        val res = fake.post("https://cam$path", body, headers)
        val out = sock.getOutputStream()
        out.write("HTTP/1.1 ${res.code} OK\r\nContent-Length: ${res.body.size}\r\nConnection: close\r\n\r\n".toByteArray())
        out.write(res.body); out.flush()
    }
}

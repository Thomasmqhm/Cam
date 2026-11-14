package com.camctl.core

import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class HttpResult(val code: Int, val body: ByteArray) {
    val text: String get() = String(body, Charsets.UTF_8)
}

/** Seam between the protocol and the network, so the protocol can be tested against a simulated camera. */
fun interface HttpPoster {
    fun post(url: String, body: ByteArray, headers: Map<String, String>): HttpResult
}

/**
 * HTTPS client for the camera's control port (443). Tapo cameras present a self-signed
 * certificate, so — as the official app does — the certificate is not verified. This client
 * is only ever pointed at an address on the local network chosen by the user, never the internet,
 * and bypasses any configured HTTP proxy.
 */
class JdkHttpPoster(private val timeoutMs: Int = 6000) : HttpPoster {
    private val socketFactory: SSLSocketFactory by lazy {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(trustAll), SecureRandom()) }.socketFactory
    }

    override fun post(url: String, body: ByteArray, headers: Map<String, String>): HttpResult {
        val conn = URL(url).openConnection(Proxy.NO_PROXY) as HttpURLConnection
        if (conn is HttpsURLConnection) {
            conn.sslSocketFactory = socketFactory
            conn.hostnameVerifier = HostnameVerifier { _, _ -> true }
        }
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.doOutput = true
            conn.useCaches = false
            headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
            conn.setFixedLengthStreamingMode(body.size)
            conn.outputStream.use { it.write(body) }
            val code = conn.responseCode
            val stream = if (code >= 400) conn.errorStream else conn.inputStream
            val bytes = stream?.use { it.readBytes() } ?: ByteArray(0)
            return HttpResult(code, bytes)
        } finally {
            conn.disconnect()
        }
    }
}

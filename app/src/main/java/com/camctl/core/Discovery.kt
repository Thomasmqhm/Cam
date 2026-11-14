package com.camctl.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** A host on the LAN that looks like an IP camera. */
data class FoundDevice(
    val ip: String,
    val openPorts: Set<Int> = emptySet(),
    val onvifName: String? = null,
    val onvifHardware: String? = null,
    val authHint: String? = null,
) {
    /** Tapo cameras expose 443 (control), 554 (RTSP) and 2020 (ONVIF). */
    val looksLikeTapo: Boolean get() = (443 in openPorts && (554 in openPorts || 2020 in openPorts)) || onvifName?.contains("TP-IPC", true) == true || onvifHardware != null && onvifHardware.startsWith("C", true)
    val label: String get() = listOfNotNull(onvifHardware, onvifName).joinToString(" · ").ifEmpty { "Appareil inconnu" }
}

object Discovery {
    val CAMERA_PORTS = listOf(443, 554, 2020, 8800)

    /**
     * ONVIF WS-Discovery: multicast probe on 239.255.255.250:3702. Tapo cameras answer when
     * a "camera account" is configured (that also enables ONVIF/RTSP). On Android the caller
     * must hold a WifiManager.MulticastLock.
     */
    fun onvifProbe(timeoutMs: Int = 2500): List<FoundDevice> {
        val msg = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
<e:Header><w:MessageID>uuid:${UUID.randomUUID()}</w:MessageID><w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To><w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>
<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>""".toByteArray()
        val found = LinkedHashMap<String, FoundDevice>()
        DatagramSocket().use { sock ->
            sock.soTimeout = 300
            val group = InetAddress.getByName("239.255.255.250")
            repeat(2) { sock.send(DatagramPacket(msg, msg.size, group, 3702)) }
            val deadline = System.currentTimeMillis() + timeoutMs
            val buf = ByteArray(16384)
            while (System.currentTimeMillis() < deadline) {
                val pkt = DatagramPacket(buf, buf.size)
                try { sock.receive(pkt) } catch (_: SocketTimeoutException) { continue }
                val xml = String(pkt.data, 0, pkt.length, Charsets.UTF_8)
                val ip = pkt.address.hostAddress ?: continue
                found[ip] = parseOnvif(ip, xml)
            }
        }
        return found.values.toList()
    }

    internal fun parseOnvif(ip: String, xml: String): FoundDevice {
        val scopes = Regex("<[^>]*Scopes[^>]*>([^<]*)<").find(xml)?.groupValues?.get(1).orEmpty()
        fun scope(key: String) = Regex("onvif://www\\.onvif\\.org/$key/([^\\s]+)").find(scopes)?.groupValues?.get(1)
            ?.let { java.net.URLDecoder.decode(it, "UTF-8") }
        return FoundDevice(ip, setOf(2020), onvifName = scope("name"), onvifHardware = scope("hardware"))
    }

    /** TCP sweep of a /24 for the camera ports. [prefix] is like "192.168.1". */
    fun scanSubnet(prefix: String, ports: List<Int> = CAMERA_PORTS, timeoutMs: Int = 350, onProgress: (Int) -> Unit = {}): List<FoundDevice> {
        val pool = Executors.newFixedThreadPool(64)
        val result = ConcurrentHashMap<String, MutableSet<Int>>()
        val done = java.util.concurrent.atomic.AtomicInteger()
        for (i in 1..254) {
            pool.execute {
                val ip = "$prefix.$i"
                for (p in ports) {
                    try {
                        Socket(java.net.Proxy.NO_PROXY).use { it.connect(InetSocketAddress(ip, p), timeoutMs) }
                        result.getOrPut(ip) { ConcurrentHashMap.newKeySet() }.add(p)
                    } catch (_: Exception) {
                    }
                }
                onProgress(done.incrementAndGet())
            }
        }
        pool.shutdown()
        pool.awaitTermination(2, TimeUnit.MINUTES)
        return result.map { (ip, ps) -> FoundDevice(ip, ps.toSortedSet()) }.sortedBy { it.ip.substringAfterLast('.').toInt() }
    }

    /**
     * Asks one host which Tapo login it offers (login/discover, no password sent).
     * Returns null if the host does not speak the Tapo API.
     */
    fun identify(ip: String, http: HttpPoster = JdkHttpPoster(2500)): String? = try {
        val r = parseObject(http.post("https://$ip/", jo("method" to "login", "params" to jo("sub_method" to "discover")).toString().toByteArray(),
            mapOf("Content-Type" to "application/json", "User-Agent" to "Tapo CameraClient Android", "requestByApp" to "true")).text)
        when {
            2 in r.intList("result", "tpap", "pake") -> "Tapo · TPAP"
            r.errorCode() == -40413 -> "Tapo · encrypt_type 3"
            r.has("error_code") -> "Tapo (code ${r.errorCode()})"
            else -> null
        }
    } catch (_: Exception) { null }

    fun merge(a: List<FoundDevice>, b: List<FoundDevice>): List<FoundDevice> {
        val m = LinkedHashMap<String, FoundDevice>()
        for (d in a + b) {
            val prev = m[d.ip]
            m[d.ip] = if (prev == null) d else prev.copy(
                openPorts = prev.openPorts + d.openPorts,
                onvifName = prev.onvifName ?: d.onvifName,
                onvifHardware = prev.onvifHardware ?: d.onvifHardware,
                authHint = prev.authHint ?: d.authHint,
            )
        }
        return m.values.sortedWith(compareByDescending<FoundDevice> { it.looksLikeTapo }.thenBy { it.ip.substringAfterLast('.').toIntOrNull() ?: 0 })
    }
}

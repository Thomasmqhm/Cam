package com.camctl.core

import java.security.MessageDigest

/**
 * SHA-256-crypt ("$5$", U. Drepper) as the Tapo app applies it to the passcode when the
 * camera's pake_register reply asks for `password_shadow` with passwd_id 5.
 * The salt is cut to 16 characters and the full "$5$[rounds=N$]salt$hash" string is returned.
 */
object Sha256Crypt {
    private const val B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    private val ORDER = arrayOf(
        intArrayOf(0, 10, 20), intArrayOf(21, 1, 11), intArrayOf(12, 22, 2), intArrayOf(3, 13, 23),
        intArrayOf(24, 4, 14), intArrayOf(15, 25, 5), intArrayOf(6, 16, 26), intArrayOf(27, 7, 17),
        intArrayOf(18, 28, 8), intArrayOf(9, 19, 29),
    )

    private fun to64(value: Int, n: Int): String {
        var v = value
        val sb = StringBuilder()
        repeat(n) { sb.append(B64[v and 0x3F]); v = v ushr 6 }
        return sb.toString()
    }

    private fun repeatTo(d: ByteArray, len: Int): ByteArray = ByteArray(len) { d[it % d.size] }

    private fun sha(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        parts.forEach { md.update(it) }
        return md.digest()
    }

    fun crypt(key: String, prefix: String): String {
        var rest = if (prefix.startsWith("$5$")) prefix.substring(3) else prefix
        var rounds = 5000
        var explicit = false
        if (rest.startsWith("rounds=")) {
            val idx = rest.indexOf('$')
            if (idx >= 0 && idx + 1 < rest.length) {
                rounds = rest.substring(7, idx).toInt().coerceIn(1000, 999_999_999)
                rest = rest.substring(idx + 1)
                explicit = true
            }
        }
        val end = rest.indexOf('$')
        val salt = rest.substring(0, minOf(if (end > 0) end else rest.length, 16))
        val k = key.toByteArray(Charsets.UTF_8)
        val s = salt.toByteArray(Charsets.UTF_8)

        val b = sha(k, s, k)
        val mdA = MessageDigest.getInstance("SHA-256")
        mdA.update(k); mdA.update(s); mdA.update(repeatTo(b, k.size))
        var n = k.size
        while (n > 0) {
            mdA.update(if (n and 1 != 0) b else k)
            n = n ushr 1
        }
        val a = mdA.digest()

        val mdP = MessageDigest.getInstance("SHA-256")
        repeat(k.size) { mdP.update(k) }
        val p = repeatTo(mdP.digest(), k.size)

        val mdS = MessageDigest.getInstance("SHA-256")
        repeat(16 + (a[0].toInt() and 0xFF)) { mdS.update(s) }
        val sb = repeatTo(mdS.digest(), s.size)

        var c = a
        for (i in 0 until rounds) {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(if (i and 1 != 0) p else c)
            if (i % 3 != 0) md.update(sb)
            if (i % 7 != 0) md.update(p)
            md.update(if (i and 1 != 0) c else p)
            c = md.digest()
        }
        fun u(i: Int) = c[i].toInt() and 0xFF
        val enc = StringBuilder()
        for (o in ORDER) enc.append(to64((u(o[0]) shl 16) or (u(o[1]) shl 8) or u(o[2]), 4))
        enc.append(to64((u(31) shl 8) or u(30), 3))
        val roundsPart = if (explicit) "rounds=$rounds$" else ""
        return "$5$$roundsPart$salt$$enc"
    }
}

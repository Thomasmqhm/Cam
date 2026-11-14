package com.camctl.core

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Primitives used by the three Tapo local login schemes. Pure JDK, works on Android. */
object Crypto {
    private val HEX = "0123456789abcdef".toCharArray()

    fun hex(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            out[i * 2] = HEX[v ushr 4]
            out[i * 2 + 1] = HEX[v and 0x0F]
        }
        return String(out)
    }

    fun unhex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    fun md5(data: ByteArray): ByteArray = MessageDigest.getInstance("MD5").digest(data)
    fun sha1(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(data)
    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun md5Hex(text: String): String = hex(md5(text.toByteArray(Charsets.UTF_8)))
    fun md5HexUpper(text: String): String = md5Hex(text).uppercase()
    fun sha256HexUpper(text: String): String = hex(sha256(text.toByteArray(Charsets.UTF_8))).uppercase()

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** RFC 5869 HKDF-SHA256. A null salt means 32 zero bytes. */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        val prk = hmacSha256(salt ?: ByteArray(32), ikm)
        val out = java.io.ByteArrayOutputStream()
        var t = ByteArray(0)
        var i = 1
        while (out.size() < length) {
            t = hmacSha256(prk, t + info + byteArrayOf(i.toByte()))
            out.write(t)
            i++
        }
        return out.toByteArray().copyOf(length)
    }

    /** RFC 8018 PBKDF2-HMAC-SHA256 (done by hand so the password is used as raw bytes on every platform). */
    fun pbkdf2Sha256(password: ByteArray, salt: ByteArray, iterations: Int, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(password, "HmacSHA256"))
        val out = java.io.ByteArrayOutputStream()
        var block = 1
        while (out.size() < length) {
            mac.update(salt)
            mac.update(byteArrayOf((block ushr 24).toByte(), (block ushr 16).toByte(), (block ushr 8).toByte(), block.toByte()))
            var u = mac.doFinal()
            val t = u.copyOf()
            for (it in 1 until iterations) {
                u = mac.doFinal(u)
                for (k in t.indices) t[k] = (t[k].toInt() xor u[k].toInt()).toByte()
            }
            out.write(t)
            block++
        }
        return out.toByteArray().copyOf(length)
    }

    fun aesCbcEncrypt(key: ByteArray, iv: ByteArray, plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return c.doFinal(plain)
    }

    fun aesCbcDecrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return c.doFinal(data)
    }

    private fun aesBlock(key: ByteArray): (ByteArray) -> ByteArray {
        val c = Cipher.getInstance("AES/ECB/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return { block -> c.doFinal(block) }
    }

    /**
     * AES-CCM (RFC 3610) with a 16-byte tag and no associated data, as used by TPAP.
     * Implemented on top of AES-ECB because neither the JDK nor Android ship CCM.
     * Returns ciphertext || tag.
     */
    fun aesCcmEncrypt(key: ByteArray, nonce: ByteArray, plain: ByteArray): ByteArray {
        val e = aesBlock(key)
        val tag = ccmMac(e, nonce, plain)
        val ct = ccmCtr(e, nonce, plain)
        val s0 = e(ctrBlock(nonce, 0))
        for (i in 0 until 16) tag[i] = (tag[i].toInt() xor s0[i].toInt()).toByte()
        return ct + tag
    }

    /** Decrypts ciphertext || tag; throws [SecurityException] if the tag does not verify. */
    fun aesCcmDecrypt(key: ByteArray, nonce: ByteArray, data: ByteArray): ByteArray {
        require(data.size >= 16) { "CCM data too short" }
        val e = aesBlock(key)
        val ct = data.copyOfRange(0, data.size - 16)
        val tag = data.copyOfRange(data.size - 16, data.size)
        val plain = ccmCtr(e, nonce, ct)
        val expected = ccmMac(e, nonce, plain)
        val s0 = e(ctrBlock(nonce, 0))
        for (i in 0 until 16) expected[i] = (expected[i].toInt() xor s0[i].toInt()).toByte()
        if (!MessageDigest.isEqual(expected, tag)) throw SecurityException("CCM tag mismatch")
        return plain
    }

    private fun lenField(nonce: ByteArray): Int = 15 - nonce.size

    private fun ctrBlock(nonce: ByteArray, counter: Int): ByteArray {
        val l = lenField(nonce)
        val b = ByteArray(16)
        b[0] = (l - 1).toByte()
        System.arraycopy(nonce, 0, b, 1, nonce.size)
        var c = counter
        for (i in 15 downTo 16 - l) { b[i] = (c and 0xFF).toByte(); c = c ushr 8 }
        return b
    }

    private fun ccmMac(e: (ByteArray) -> ByteArray, nonce: ByteArray, plain: ByteArray): ByteArray {
        val l = lenField(nonce)
        val b0 = ByteArray(16)
        b0[0] = ((((16 - 2) / 2) shl 3) or (l - 1)).toByte()
        System.arraycopy(nonce, 0, b0, 1, nonce.size)
        var len = plain.size
        for (i in 15 downTo 16 - l) { b0[i] = (len and 0xFF).toByte(); len = len ushr 8 }
        var x = e(b0)
        var off = 0
        while (off < plain.size) {
            val blk = ByteArray(16)
            val n = minOf(16, plain.size - off)
            System.arraycopy(plain, off, blk, 0, n)
            for (i in 0 until 16) blk[i] = (blk[i].toInt() xor x[i].toInt()).toByte()
            x = e(blk)
            off += 16
        }
        return x
    }

    private fun ccmCtr(e: (ByteArray) -> ByteArray, nonce: ByteArray, input: ByteArray): ByteArray {
        val out = ByteArray(input.size)
        var off = 0
        var counter = 1
        while (off < input.size) {
            val s = e(ctrBlock(nonce, counter++))
            val n = minOf(16, input.size - off)
            for (i in 0 until n) out[off + i] = (input[off + i].toInt() xor s[i].toInt()).toByte()
            off += 16
        }
        return out
    }
}

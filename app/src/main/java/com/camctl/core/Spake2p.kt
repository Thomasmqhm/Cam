package com.camctl.core

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/**
 * SPAKE2+ on P-256 with the RFC 9383 M/N points, as used by the TPAP local login of
 * recent Tapo camera firmware. Affine arithmetic with BigInteger: slow-ish but only
 * runs a handful of scalar multiplications per login.
 */
object P256 {
    private val TWO = BigInteger.valueOf(2)
    private val THREE = BigInteger.valueOf(3)

    val P = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
    val A: BigInteger = P - BigInteger.valueOf(3)
    val B = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
    val N = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    val G = Point(
        BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
        BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16),
    )
    val M = decode(Crypto.unhex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"))!!
    val NPt = decode(Crypto.unhex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"))!!

    data class Point(val x: BigInteger, val y: BigInteger)

    fun add(p1: Point?, p2: Point?): Point? {
        if (p1 == null) return p2
        if (p2 == null) return p1
        if (p1.x == p2.x && (p1.y + p2.y).mod(P).signum() == 0) return null
        val m = if (p1 == p2) {
            (THREE * p1.x * p1.x + A).mod(P) * (TWO * p1.y).modInverse(P)
        } else {
            (p2.y - p1.y).mod(P) * (p2.x - p1.x).mod(P).modInverse(P)
        }.mod(P)
        val x3 = (m * m - p1.x - p2.x).mod(P)
        return Point(x3, (m * (p1.x - x3) - p1.y).mod(P))
    }

    fun mul(k0: BigInteger, p: Point?): Point? {
        var k = k0.mod(N)
        var result: Point? = null
        var addend = p
        while (k.signum() > 0) {
            if (k.testBit(0)) result = add(result, addend)
            addend = add(addend, addend)
            k = k.shiftRight(1)
        }
        return result
    }

    fun neg(p: Point?): Point? = p?.let { Point(it.x, (-it.y).mod(P)) }

    fun isOnCurve(p: Point): Boolean =
        (p.y * p.y - (p.x * p.x * p.x + A * p.x + B)).mod(P).signum() == 0

    fun decode(b: ByteArray): Point? {
        return when (b[0].toInt()) {
            0x04 -> Point(BigInteger(1, b.copyOfRange(1, 33)), BigInteger(1, b.copyOfRange(33, 65)))
            0x02, 0x03 -> {
                val x = BigInteger(1, b.copyOfRange(1, 33))
                var y = (x.modPow(THREE, P) + A * x + B).mod(P).modPow((P + BigInteger.ONE).shiftRight(2), P)
                if (y.testBit(0) != ((b[0].toInt() and 1) == 1)) y = P - y
                Point(x, y)
            }
            else -> null
        }
    }

    fun to32(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size > 32 -> raw.copyOfRange(raw.size - 32, raw.size)
            else -> ByteArray(32 - raw.size) + raw
        }
    }

    fun encode(p: Point): ByteArray = byteArrayOf(4) + to32(p.x) + to32(p.y)
}

/** Client side of one pake_register -> pake_share exchange. */
class Spake2pClient(
    devSalt: ByteArray,
    iterations: Int,
    devShare: ByteArray,
    userRandom: ByteArray,
    devRandom: ByteArray,
    credential: String,
    randomScalar: BigInteger,
) {
    val userShare: ByteArray
    val userConfirm: ByteArray
    private val kcB: ByteArray
    private val sharedKey: ByteArray

    init {
        val dk = Crypto.pbkdf2Sha256(credential.toByteArray(Charsets.UTF_8), devSalt, iterations, 80)
        val w0 = BigInteger(1, dk.copyOfRange(0, 40)).mod(P256.N)
        val w1 = BigInteger(1, dk.copyOfRange(40, 80)).mod(P256.N)
        val y = P256.decode(devShare) ?: throw TapoException(null, "dev_share invalide")
        require(P256.isOnCurve(y)) { "dev_share hors de la courbe" }
        val x = randomScalar.mod(P256.N - BigInteger.ONE) + BigInteger.ONE
        val bigX = P256.add(P256.mul(x, P256.G), P256.mul(w0, P256.M))!!
        val h = P256.add(y, P256.neg(P256.mul(w0, P256.NPt)))
        userShare = P256.encode(bigX)
        val yb = P256.encode(y)
        val context = Crypto.sha256("PAKE V1".toByteArray() + userRandom + devRandom)
        val tt = lenPrefixed(
            context, ByteArray(0), ByteArray(0),
            P256.encode(P256.M), P256.encode(P256.NPt),
            userShare, yb,
            P256.encode(P256.mul(x, h)!!), P256.encode(P256.mul(w1, h)!!),
            P256.to32(w0),
        )
        val ke = Crypto.sha256(tt)
        val conf = Crypto.hkdfSha256(ke, null, "ConfirmationKeys".toByteArray(), 64)
        kcB = conf.copyOfRange(32, 64)
        userConfirm = Crypto.hmacSha256(conf.copyOfRange(0, 32), yb)
        sharedKey = Crypto.hkdfSha256(ke, null, "SharedKey".toByteArray(), 32)
    }

    fun deviceConfirmOk(devConfirm: ByteArray): Boolean =
        MessageDigest.isEqual(devConfirm, Crypto.hmacSha256(kcB, userShare))

    /** AES-128 key and 12-byte base nonce for the /ds channel. */
    fun sessionKeyAndNonce(): Pair<ByteArray, ByteArray> {
        val key = Crypto.hkdfSha256(sharedKey, "tp-kdf-salt-aes128-key".toByteArray(), "tp-kdf-info-aes128-key".toByteArray(), 32).copyOf(16)
        val nonce = Crypto.hkdfSha256(sharedKey, "tp-kdf-salt-aes128-iv".toByteArray(), "tp-kdf-info-aes128-iv".toByteArray(), 32).copyOf(12)
        return key to nonce
    }

    companion object {
        fun lenPrefixed(vararg chunks: ByteArray): ByteArray {
            val out = java.io.ByteArrayOutputStream()
            for (c in chunks) {
                out.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(c.size.toLong()).array())
                out.write(c)
            }
            return out.toByteArray()
        }

        /**
         * Turns a passcode into the credential the camera asked for in pake_register
         * (`extra_crypt`): passwd_id 5 = SHA-256-crypt with the given prefix, 2 = SHA-1 hex.
         */
        fun applyExtraCrypt(passcode: String, type: String?, passwdId: Int?, prefix: String?): String {
            if (type.isNullOrEmpty()) return passcode
            if (type.lowercase() != "password_shadow") throw TapoException(null, "extra_crypt non supporté: $type")
            return when (passwdId ?: 0) {
                5 -> Sha256Crypt.crypt(passcode, prefix ?: "")
                2 -> Crypto.hex(Crypto.sha1(passcode.toByteArray()))
                else -> throw TapoException(null, "passwd_id non supporté: $passwdId")
            }
        }
    }
}

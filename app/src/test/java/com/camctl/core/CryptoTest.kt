package com.camctl.core

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.CCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.math.BigInteger
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Each primitive is checked against an independent implementation (BouncyCastle, JDK, OpenSSL). */
class CryptoTest {
    private val rnd = Random(1234)

    @Test
    fun ccmMatchesBouncyCastle() {
        for (len in listOf(0, 1, 15, 16, 17, 31, 32, 100, 1000)) {
            val key = rnd.nextBytes(16)
            val nonce = rnd.nextBytes(12)
            val plain = rnd.nextBytes(len)
            val bc = CCMBlockCipher.newInstance(AESEngine.newInstance())
            bc.init(true, AEADParameters(KeyParameter(key), 128, nonce))
            val expected = ByteArray(bc.getOutputSize(plain.size))
            bc.doFinal(expected, bc.processBytes(plain, 0, plain.size, expected, 0))
            val mine = Crypto.aesCcmEncrypt(key, nonce, plain)
            assertContentEquals(expected, mine, "len=$len")
            assertContentEquals(plain, Crypto.aesCcmDecrypt(key, nonce, mine))
        }
    }

    @Test
    fun ccmRejectsTamperedData() {
        val key = rnd.nextBytes(16); val nonce = rnd.nextBytes(12)
        val ct = Crypto.aesCcmEncrypt(key, nonce, "hello camera".toByteArray())
        ct[3] = (ct[3].toInt() xor 1).toByte()
        assertFailsWith<SecurityException> { Crypto.aesCcmDecrypt(key, nonce, ct) }
    }

    @Test
    fun hkdfMatchesBouncyCastle() {
        for (salt in listOf(null, "tp-kdf-salt-aes128-key".toByteArray())) {
            val ikm = rnd.nextBytes(32)
            val info = "ConfirmationKeys".toByteArray()
            val gen = HKDFBytesGenerator(SHA256Digest())
            gen.init(HKDFParameters(ikm, salt ?: ByteArray(32), info))
            val expected = ByteArray(64).also { gen.generateBytes(it, 0, 64) }
            assertContentEquals(expected, Crypto.hkdfSha256(ikm, salt, info, 64))
        }
    }

    @Test
    fun hkdfRfc5869Case1() {
        val okm = Crypto.hkdfSha256(
            Crypto.unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            Crypto.unhex("000102030405060708090a0b0c"),
            Crypto.unhex("f0f1f2f3f4f5f6f7f8f9"), 42,
        )
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", Crypto.hex(okm))
    }

    @Test
    fun pbkdf2MatchesJdk() {
        val pw = "\$5\$Xy9zSalt\$abc0123"
        val salt = rnd.nextBytes(16)
        val jdk = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(PBEKeySpec(pw.toCharArray(), salt, 1000, 640)).encoded
        assertContentEquals(jdk, Crypto.pbkdf2Sha256(pw.toByteArray(), salt, 1000, 80))
    }

    @Test
    fun sha256CryptMatchesOpenssl() {
        // Reference values produced with `openssl passwd -5 -salt <salt> <key>` (OpenSSL 3.0.13).
        val cases = listOf(
            Triple("Hello world!", "saltstring", "\$5\$saltstring\$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"),
            Triple("Hello world!", "saltstringsaltstring", "\$5\$saltstringsaltst\$a5C8Ofk71MUIoKve2QuP9FMl.dwNgseF5tR1LGAL7iB"),
            Triple("S3cret-Pässword!", "Xy9zSalt", "\$5\$Xy9zSalt\$3XVCPkzIJVNXXXjRJKxXjdFWt0fIQ/KfUYrtIseqpV/"),
            Triple("S3cret-Pässword!", "abcdefghijklmnopqrstuvwxyz", "\$5\$abcdefghijklmnop\$Tto5dolKJJDusW22u6fDkD3od.bnt8I/tNOUjQ7L7C8"),
            Triple("S3cret-Pässword!", "a", "\$5\$a\$11p5AxpJL24uM9T2Pml9lb1RinUw3jKJ7BdSFr2D.65"),
            Triple("0123456789abcdef0123456789abcdef", "Xy9zSalt", "\$5\$Xy9zSalt\$TSjjJ0kg6h3dgGzwPBNwEh61WOqO9K6FypIyFOvfnQ5"),
            Triple("0123456789abcdef0123456789abcdef", "abcdefghijklmnopqrstuvwxyz", "\$5\$abcdefghijklmnop\$EXc4R8dpfUV1jwquc8YYq8GqbSSTnh.x3kbZR4yEnWB"),
            Triple("x", "Xy9zSalt", "\$5\$Xy9zSalt\$G/ec9qoQ6WZUXgS.E5ftvNgActipzA0NKV6AaMoNXj3"),
            Triple("x", "a", "\$5\$a\$m5PPB7rYZmTs0gzCcO.9R/qmXtGr3g/5s2bl1flV9x2"),
        )
        for ((key, salt, expected) in cases) {
            assertEquals(expected, Sha256Crypt.crypt(key, "\$5\$$salt"), "$key / $salt")
            assertEquals(expected, Sha256Crypt.crypt(key, "\$5\$$salt\$whatever"), "prefix with trailing hash")
        }
    }

    @Test
    fun p256BasicIdentities() {
        assertTrue(P256.isOnCurve(P256.G))
        assertTrue(P256.isOnCurve(P256.M))
        assertTrue(P256.isOnCurve(P256.NPt))
        assertEquals(null, P256.mul(P256.N, P256.G), "n·G = infinity")
        val a = BigInteger(256, SecureRandom()); val b = BigInteger(256, SecureRandom())
        assertEquals(P256.mul(a * b, P256.G), P256.mul(a, P256.mul(b, P256.G)))
        assertEquals(P256.add(P256.mul(a, P256.G), P256.mul(b, P256.G)), P256.mul(a + b, P256.G))
    }

    @Test
    fun p256MatchesJdkKeyAgreement() {
        // ECDH with the JDK: our x·(Y) must equal the JDK's shared secret.
        val kpg = java.security.KeyPairGenerator.getInstance("EC").apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }
        val kp = kpg.generateKeyPair()
        val pub = kp.public as java.security.interfaces.ECPublicKey
        val k = BigInteger(256, SecureRandom()).mod(P256.N)
        val myPub = P256.mul(k, P256.G)!!
        val spec = java.security.spec.ECPublicKeySpec(java.security.spec.ECPoint(myPub.x, myPub.y), pub.params)
        val myPubKey = java.security.KeyFactory.getInstance("EC").generatePublic(spec)
        val ka = javax.crypto.KeyAgreement.getInstance("ECDH").apply { init(kp.private); doPhase(myPubKey, true) }
        val jdkSecret = ka.generateSecret()
        val mine = P256.mul(k, P256.Point(pub.w.affineX, pub.w.affineY))!!
        assertContentEquals(jdkSecret, P256.to32(mine.x))
    }

    @Test
    fun spake2pAgreesWithRfc9383Verifier() {
        val credential = Sha256Crypt.crypt(Crypto.md5Hex("my password"), "\$5\$Xy9zSalt")
        val salt = rnd.nextBytes(16); val iterations = 1000
        val userRandom = rnd.nextBytes(32); val devRandom = rnd.nextBytes(32)
        val cam = FakeSpakeVerifier(credential, salt, iterations, devRandom)
        val client = Spake2pClient(salt, iterations, cam.devShare, userRandom, devRandom, credential, BigInteger(256, SecureRandom()))
        val camResult = cam.finish(client.userShare, userRandom)
        assertContentEquals(camResult.expectedUserConfirm, client.userConfirm, "camera accepts client's proof")
        assertTrue(client.deviceConfirmOk(camResult.devConfirm), "client accepts camera's proof")
        assertContentEquals(camResult.key, client.sessionKeyAndNonce().first)
        assertContentEquals(camResult.nonce, client.sessionKeyAndNonce().second)
    }

    @Test
    fun spake2pWrongPasswordIsDetected() {
        val salt = rnd.nextBytes(16); val devRandom = rnd.nextBytes(32); val userRandom = rnd.nextBytes(32)
        val cam = FakeSpakeVerifier("right", salt, 1000, devRandom)
        val client = Spake2pClient(salt, 1000, cam.devShare, userRandom, devRandom, "wrong", BigInteger(256, SecureRandom()))
        val camResult = cam.finish(client.userShare, userRandom)
        assertTrue(!camResult.expectedUserConfirm.contentEquals(client.userConfirm))
        assertTrue(!client.deviceConfirmOk(camResult.devConfirm))
    }
}

/**
 * Camera ("verifier") side of SPAKE2+ written from RFC 9383 §3.3–3.4 independently of the client:
 * Y = y·G + w0·N, Z = y·(X − w0·M), V = y·L with L = w1·G.
 */
class FakeSpakeVerifier(credential: String, salt: ByteArray, iterations: Int, private val devRandom: ByteArray) {
    private val w0: BigInteger
    private val l: P256.Point
    private val y = BigInteger(256, SecureRandom()).mod(P256.N - BigInteger.ONE) + BigInteger.ONE
    val devShare: ByteArray

    init {
        val dk = Crypto.pbkdf2Sha256(credential.toByteArray(), salt, iterations, 80)
        w0 = BigInteger(1, dk.copyOfRange(0, 40)).mod(P256.N)
        val w1 = BigInteger(1, dk.copyOfRange(40, 80)).mod(P256.N)
        l = P256.mul(w1, P256.G)!!
        devShare = P256.encode(P256.add(P256.mul(y, P256.G), P256.mul(w0, P256.NPt))!!)
    }

    class Result(val expectedUserConfirm: ByteArray, val devConfirm: ByteArray, val key: ByteArray, val nonce: ByteArray)

    fun finish(userShare: ByteArray, userRandom: ByteArray): Result {
        val x = P256.decode(userShare)!!
        val z = P256.mul(y, P256.add(x, P256.neg(P256.mul(w0, P256.M))))!!
        val v = P256.mul(y, l)!!
        val context = Crypto.sha256("PAKE V1".toByteArray() + userRandom + devRandom)
        val tt = Spake2pClient.lenPrefixed(context, ByteArray(0), ByteArray(0), P256.encode(P256.M), P256.encode(P256.NPt),
            userShare, devShare, P256.encode(z), P256.encode(v), P256.to32(w0))
        val k = Crypto.sha256(tt)
        val conf = Crypto.hkdfSha256(k, null, "ConfirmationKeys".toByteArray(), 64)
        val shared = Crypto.hkdfSha256(k, null, "SharedKey".toByteArray(), 32)
        return Result(
            expectedUserConfirm = Crypto.hmacSha256(conf.copyOfRange(0, 32), devShare),
            devConfirm = Crypto.hmacSha256(conf.copyOfRange(32, 64), userShare),
            key = Crypto.hkdfSha256(shared, "tp-kdf-salt-aes128-key".toByteArray(), "tp-kdf-info-aes128-key".toByteArray(), 32).copyOf(16),
            nonce = Crypto.hkdfSha256(shared, "tp-kdf-salt-aes128-iv".toByteArray(), "tp-kdf-info-aes128-iv".toByteArray(), 32).copyOf(12),
        )
    }
}

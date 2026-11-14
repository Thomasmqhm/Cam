package com.camctl.core

import org.json.JSONArray

import org.json.JSONObject
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Base64

class TapoException(val code: Int?, message: String) : Exception(message)

/** The three local login schemes Tapo cameras use, depending on firmware age. */
enum class AuthMode(val label: String) {
    LEGACY("Ancien (mot de passe MD5)"),
    SECURE_V3("Sécurisé encrypt_type 3 (AES-CBC)"),
    TPAP("TPAP / SPAKE2+ (AES-CCM)"),
}

/**
 * Talks to a Tapo camera over its local HTTPS API (port 443), exactly the channel the
 * official app uses when the phone is on the same network as the camera.
 *
 * All commands go to POST https://<ip>/stok=<token>/ds as
 * {"method":"multipleRequest","params":{"requests":[{"method":...,"params":...}]}}.
 * Only the way the token is obtained and the body is wrapped differs per [AuthMode].
 *
 * @param password the password of the TP-Link (cloud) account that owns the camera —
 *                 the camera uses it as the local "admin" password.
 */
class TapoClient(
    val host: String,
    private val password: String,
    val port: Int = 443,
    private val http: HttpPoster = JdkHttpPoster(),
    private val log: (String) -> Unit = {},
    private val random: SecureRandom = SecureRandom(),
    private val clock: () -> Long = { System.currentTimeMillis() },
) {
    private val base = "https://$host:$port"
    var mode: AuthMode? = null
        private set
    private var tpapInfo: JSONObject? = null
    private var session: Session? = null

    private interface Session {
        fun send(request: JSONObject): JSONObject
        fun valid(): Boolean = true
    }

    // ------------------------------------------------------------------ public API

    /** Runs one camera function and returns its `result` object; throws [TapoException] on error. */
    @Synchronized
    fun call(method: String, params: Any? = null): JSONObject {
        val r = multi(listOf(if (params == null) jo("method" to method) else jo("method" to method, "params" to params))).first()
        val code = r.errorCode()
        if (code != 0) throw TapoException(code, "$method: ${TapoErrors.describe(code)}")
        return r.optJSONObject("result") ?: JSONObject()
    }

    /** Sends several sub-requests in one multipleRequest and returns each raw sub-response. */
    @Synchronized
    fun multi(requests: List<JSONObject>): List<JSONObject> {
        val resp = send(jo("method" to "multipleRequest", "params" to jo("requests" to requests)))
        val code = resp.errorCode()
        if (code != 0) throw TapoException(code, TapoErrors.describe(code))
        val list = resp.at("result", "responses") as? JSONArray
            ?: throw TapoException(null, "Réponse inattendue: $resp")
        return list.objects()
    }

    /** Sends any top-level request (used by the raw console and by "do" style commands). */
    @Synchronized
    fun send(request: JSONObject): JSONObject {
        for (attempt in 0..1) {
            val s = session?.takeIf { it.valid() } ?: login()
            val resp = try {
                s.send(request)
            } catch (e: TapoException) {
                if (attempt == 0 && e.code in SESSION_ERRORS) { log("Session expirée (${e.code}), reconnexion"); session = null; continue }
                throw e
            }
            if (attempt == 0 && resp.errorCode() in SESSION_ERRORS) {
                log("Session expirée (${resp.errorCode()}), reconnexion")
                session = null
                continue
            }
            return resp
        }
        throw TapoException(null, "unreachable")
    }

    @Synchronized
    fun logout() { session = null }

    /** Asks the camera which login it offers, without sending any password. */
    @Synchronized
    fun detectMode(): AuthMode {
        mode?.let { return it }
        val discover = runCatching { postLogin(jo("sub_method" to "discover")) }.getOrNull()
        log("login/discover → ${discover ?: "pas de réponse"}")
        val tpap = discover?.at("result", "tpap") as? JSONObject
        val detected = when {
            tpap != null && 2 in tpap.intList("pake") -> { tpapInfo = tpap; AuthMode.TPAP }
            discover != null && offersV3(discover) -> AuthMode.SECURE_V3
            else -> {
                val probe = postLogin(jo("encrypt_type" to "3", "username" to USER, "cnonce" to nonceHex(8)))
                log("sonde encrypt_type 3 → $probe")
                when {
                    probe.errorCode() == -40211 -> AuthMode.TPAP
                    offersV3(probe) -> AuthMode.SECURE_V3
                    else -> AuthMode.LEGACY
                }
            }
        }
        log("Mode d'authentification: ${detected.label}")
        mode = detected
        return detected
    }

    /** Logs in now (otherwise done lazily by the first command). */
    @Synchronized
    fun connect() { login() }

    private fun login(): Session {
        if (password.isEmpty()) throw TapoException(null, "Mot de passe vide")
        val s = when (detectMode()) {
            AuthMode.LEGACY -> loginLegacy()
            AuthMode.SECURE_V3 -> loginSecure()
            AuthMode.TPAP -> loginTpap()
        }
        session = s
        return s
    }

    // ------------------------------------------------------------------ transport helpers

    private fun headers(contentType: String = "application/json; charset=UTF-8") = linkedMapOf(
        "Host" to "$host:$port",
        "Referer" to base,
        "Accept" to "application/json",
        "User-Agent" to "Tapo CameraClient Android",
        "requestByApp" to "true",
        "Content-Type" to contentType,
    )

    private fun postJson(url: String, body: JSONObject, extra: Map<String, String> = emptyMap()): JSONObject {
        val res = http.post(url, body.toString().toByteArray(), headers() + extra)
        if (res.body.isEmpty()) throw TapoException(null, "Réponse vide (HTTP ${res.code})")
        return parseObject(res.text)
    }

    private fun postLogin(params: JSONObject): JSONObject = postJson("$base/", jo("method" to "login", "params" to params))

    private fun offersV3(r: JSONObject) = r.errorCode() == -40413 && "3" in r.stringList("result", "data", "encrypt_type")

    private fun nonceHex(bytes: Int): String = Crypto.hex(ByteArray(bytes).also { random.nextBytes(it) }).uppercase()

    private fun checkLockout(r: JSONObject) {
        for (holder in listOf(r.at("error_info"), r.at("data"), r.at("result", "data"))) {
            val left = holder.int("sec_left") ?: 0
            if (left > 0) throw TapoException(-40404, "Caméra verrouillée après trop d'essais : réessayez dans $left s")
        }
    }

    // ------------------------------------------------------------------ LEGACY

    private fun loginLegacy(): Session {
        val r = postLogin(jo("hashed" to true, "password" to Crypto.md5HexUpper(password), "username" to USER))
        checkLockout(r)
        val stok = r.str("result", "stok") ?: throw TapoException(r.errorCode(), "Connexion refusée: ${TapoErrors.describe(r.errorCode())}")
        log("Connecté (legacy)")
        val url = "$base/stok=$stok/ds"
        return object : Session {
            override fun send(request: JSONObject) = postJson(url, request)
        }
    }

    // ------------------------------------------------------------------ SECURE_V3 (encrypt_type 3)

    private fun loginSecure(): Session {
        val cnonce = nonceHex(8)
        val first = postLogin(jo("cnonce" to cnonce, "encrypt_type" to "3", "username" to USER))
        checkLockout(first)
        val nonce = first.str("result", "data", "nonce")
        val confirm = first.str("result", "data", "device_confirm")
        if (nonce == null || confirm == null) throw TapoException(first.errorCode(), "Login sécurisé: réponse inattendue $first")

        // The camera proves it knows the password; this also tells us which hash it stored.
        val candidates = listOf(Crypto.sha256HexUpper(password), Crypto.md5HexUpper(password))
        val hashed = candidates.firstOrNull { hp ->
            Crypto.sha256HexUpper(cnonce + hp + nonce) + nonce + cnonce == confirm
        } ?: throw TapoException(-40401, "Mot de passe incorrect (la caméra ne confirme pas le mot de passe)")

        val digest = Crypto.sha256HexUpper(hashed + cnonce + nonce) + cnonce + nonce
        val second = postLogin(jo("cnonce" to cnonce, "encrypt_type" to "3", "digest_passwd" to digest, "username" to USER))
        checkLockout(second)
        val stok = second.str("result", "stok")
        val startSeq = second.int("result", "start_seq")
        if (stok == null || startSeq == null) throw TapoException(second.errorCode(), "Login refusé: ${TapoErrors.describe(second.errorCode())}")
        val group = second.str("result", "user_group")
        if (group != null && group != "root") throw TapoException(null, "Compte '$group' sans droits: utilisez le mot de passe du compte TP-Link propriétaire")

        val keys = SecureV3Keys(hashed, cnonce, nonce)
        log("Connecté (encrypt_type 3, hash ${if (hashed == candidates[0]) "SHA-256" else "MD5"})")
        val url = "$base/stok=$stok/ds"
        return object : Session {
            var seq: Int = startSeq!!
            override fun send(request: JSONObject): JSONObject {
                val enc = Base64.getEncoder().encodeToString(Crypto.aesCbcEncrypt(keys.lsk, keys.ivb, request.toString().toByteArray()))
                val full = jo("method" to "securePassthrough", "params" to jo("request" to enc)).toString()
                val extra = mapOf("Seq" to seq.toString(), "Tapo_tag" to keys.tag(full, seq))
                seq++
                val res = http.post(url, full.toByteArray(), headers() + extra)
                val outer = parseObject(res.text)
                val inner = outer.str("result", "response") ?: return outer
                val plain = try {
                    Crypto.aesCbcDecrypt(keys.lsk, keys.ivb, Base64.getDecoder().decode(inner))
                } catch (e: Exception) {
                    throw TapoException(-40401, "Déchiffrement impossible, session invalide")
                }
                return parseObject(String(plain, Charsets.UTF_8))
            }
        }
    }

    /** Key material of an encrypt_type 3 session (exposed for tests). */
    class SecureV3Keys(private val hashedPassword: String, private val cnonce: String, nonce: String) {
        val lsk = token("lsk", nonce)
        val ivb = token("ivb", nonce)
        private fun token(type: String, nonce: String): ByteArray {
            val hashedKey = Crypto.sha256HexUpper(cnonce + hashedPassword + nonce)
            return Crypto.sha256((type + cnonce + nonce + hashedKey).toByteArray()).copyOf(16)
        }
        fun tag(body: String, seq: Int): String =
            Crypto.sha256HexUpper(Crypto.sha256HexUpper(hashedPassword + cnonce) + body + seq)
    }

    // ------------------------------------------------------------------ TPAP (SPAKE2+)

    private fun loginTpap(): Session {
        if (tpapInfo == null) {
            tpapInfo = runCatching { postLogin(jo("sub_method" to "discover")).at("result", "tpap") as? JSONObject }.getOrNull()
        }
        val username = if (tpapInfo.int("user_hash_type") == 1) Crypto.sha256HexUpper(USER) else Crypto.md5Hex(USER)
        // Same candidates and order as the app: md5 hex, then sha256 upper hex of the account password.
        val passcodes = listOf(Crypto.md5Hex(password), Crypto.sha256HexUpper(password))
        var last: TapoException? = null
        for (pc in passcodes) {
            try {
                return tpapWith(username, pc)
            } catch (e: TapoException) {
                last = e
                if (e.code != -40401) throw e
            }
        }
        throw TapoException(-40401, "Mot de passe incorrect (TPAP)").also { it.initCause(last) }
    }

    private fun tpapWith(username: String, passcode: String): Session {
        val userRandom = ByteArray(32).also { random.nextBytes(it) }
        val b64 = Base64.getEncoder()
        val dec = Base64.getDecoder()
        val reg = postLogin(
            jo(
                "sub_method" to "pake_register",
                "username" to username,
                "user_random" to b64.encodeToString(userRandom),
                "cipher_suites" to listOf(1),
                "encryption" to listOf("aes_128_ccm"),
                "passcode_type" to "userpw",
            )
        )
        val res = reg.optJSONObject("result") ?: throw TapoException(reg.errorCode(), "pake_register: ${TapoErrors.describe(reg.errorCode())}")
        val credential = Spake2pClient.applyExtraCrypt(
            passcode,
            res.str("extra_crypt", "type"),
            res.int("extra_crypt", "params", "passwd_id"),
            res.str("extra_crypt", "params", "passwd_prefix"),
        )
        val client = Spake2pClient(
            devSalt = dec.decode(res.str("dev_salt")!!),
            iterations = res.int("iterations")!!,
            devShare = dec.decode(res.str("dev_share")!!),
            userRandom = userRandom,
            devRandom = dec.decode(res.str("dev_random")!!),
            credential = credential,
            randomScalar = BigInteger(1, ByteArray(32).also { random.nextBytes(it) }),
        )
        val share = postLogin(
            jo(
                "sub_method" to "pake_share",
                "user_share" to b64.encodeToString(client.userShare),
                "user_confirm" to b64.encodeToString(client.userConfirm),
            )
        )
        val sr = share.optJSONObject("result")
        if (sr == null) {
            checkLockout(share)
            throw TapoException(share.errorCode(), "pake_share: ${TapoErrors.describe(share.errorCode())}")
        }
        if (!client.deviceConfirmOk(dec.decode(sr.str("dev_confirm")!!))) throw TapoException(null, "La caméra n'a pas prouvé son identité (dev_confirm)")
        val (key, baseNonce) = client.sessionKeyAndNonce()
        val stok = sr.str("stok")!!
        val expiresAt = clock() + 1000L * (sr.int("expired") ?: 3600)
        log("Connecté (TPAP)")
        val url = "$base/stok=$stok/ds"
        return object : Session {
            var seq = sr.int("start_seq")!!
            override fun valid() = clock() < expiresAt
            override fun send(request: JSONObject): JSONObject {
                val wrapped = if (request.str("method") == "multipleRequest") request
                else jo("method" to "multipleRequest", "params" to jo("requests" to listOf(request)))
                val s = seq++
                val body = seqBytes(s) + Crypto.aesCcmEncrypt(key, tpapNonce(baseNonce, s), wrapped.toString().toByteArray())
                val raw = http.post(url, body, headers("application/octet-stream") + ("Accept" to "application/octet-stream")).body
                if (raw.isNotEmpty() && raw[0] == '{'.code.toByte()) {
                    val err = parseObject(String(raw, Charsets.UTF_8))
                    throw TapoException(err.errorCode(), "Requête refusée: ${TapoErrors.describe(err.errorCode())}")
                }
                if (raw.size < 20) throw TapoException(null, "Réponse trop courte (${raw.size} octets)")
                val replySeq = ByteBuffer.wrap(raw, 0, 4).int
                val plain = try {
                    Crypto.aesCcmDecrypt(key, tpapNonce(baseNonce, replySeq), raw.copyOfRange(4, raw.size))
                } catch (e: SecurityException) {
                    throw TapoException(-40401, "Réponse non authentifiée")
                }
                val resp = parseObject(String(plain, Charsets.UTF_8))
                if (request.str("method") != "multipleRequest") {
                    (resp.at("result", "responses") as? JSONArray)?.optJSONObject(0)?.let { return it }
                }
                return resp
            }
        }
    }

    companion object {
        const val USER = "admin"
        val SESSION_ERRORS = setOf(-40401, -40421, -1)

        fun seqBytes(seq: Int): ByteArray = ByteBuffer.allocate(4).putInt(seq).array()
        fun tpapNonce(base: ByteArray, seq: Int): ByteArray = base.copyOf(8) + seqBytes(seq)
    }
}

object TapoErrors {
    private val messages = mapOf(
        -40401 to "session invalide / mot de passe refusé",
        -40404 to "appareil bloqué (trop d'essais)",
        -40413 to "nonce invalide",
        -40418 to "authentification TPAP échouée",
        -40421 to "jeton de session TPAP invalide",
        -40211 to "paramètres manquants (login non supporté par ce firmware)",
        -40209 to "identifiants invalides",
        -40210 to "méthode inexistante sur ce modèle",
        -40105 to "méthode inexistante sur ce modèle",
        -40106 to "méthode non supportée",
        -40101 to "paramètre inexistant",
        -64324 to "mode privé actif: commande impossible",
        -64302 to "préréglage introuvable",
        -64303 to "moteur occupé",
        -64304 to "butée pan/tilt atteinte",
        -64305 to "moteur en mouvement",
        -64306 to "nombre max de préréglages atteint",
        -64336 to "zone privée du moteur",
        -52405 to "trop de requêtes",
        -52419 to "trop de clients HTTPS",
        -1 to "échec générique",
    )

    fun describe(code: Int): String = messages[code]?.let { "$it ($code)" } ?: "erreur $code"
}

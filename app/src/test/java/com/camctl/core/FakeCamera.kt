package com.camctl.core

import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Base64

/**
 * In-memory simulation of a Tapo camera's HTTPS control API, written from the server's point of
 * view, used to exercise the whole client (login, encryption, sequence numbers, re-login).
 */
class FakeCamera(val mode: AuthMode, private val password: String) : HttpPoster {
    val calls = mutableListOf<String>()
    val state = mutableMapOf("privacy" to "off", "led" to "on", "motion" to "on", "track" to "off", "night" to "md_night_vision")
    val presets = mutableListOf("1" to "Porte", "2" to "Jardin")
    var moves = mutableListOf<Pair<String, String>>()
    var alarm = "stopped"
    var loginCount = 0
    var supportsNewNightVision = true

    private val rnd = SecureRandom()
    private val b64 = Base64.getEncoder()
    private val d64 = Base64.getDecoder()
    private var stok: String? = null

    // secure v3
    private var cnonce = ""; private var nonce = ""; private var keys: TapoClient.SecureV3Keys? = null; private var seq = 0
    private val storedHash get() = Crypto.sha256HexUpper(password)
    // tpap
    private val shadowPrefix = "\$5\$Kq3wSalt"
    private var verifier: FakeSpakeVerifier? = null
    private var userRandom = ByteArray(0)
    private var tpapKey = ByteArray(0); private var tpapNonce = ByteArray(0)

    fun expireSession() { stok = "expired-" + stok }

    override fun post(url: String, body: ByteArray, headers: Map<String, String>): HttpResult {
        val path = url.substringAfter("://").substringAfter("/")
        if (path.isEmpty()) return json(login(parseObject(String(body))))
        val tok = path.substringAfter("stok=").substringBefore("/ds")
        if (tok != stok) return json(jo("error_code" to -40401))
        return when (mode) {
            AuthMode.LEGACY -> json(handle(parseObject(String(body))))
            AuthMode.SECURE_V3 -> secureDs(String(body), headers)
            AuthMode.TPAP -> tpapDs(body)
        }
    }

    private fun json(o: JSONObject) = HttpResult(200, o.toString().toByteArray())
    private fun hex(n: Int) = Crypto.hex(ByteArray(n).also { rnd.nextBytes(it) }).uppercase()

    // ------------------------------------------------------------------ login endpoint

    private fun login(req: JSONObject): JSONObject {
        val p = req.getJSONObject("params")
        val sub = p.str("sub_method")
        return when (mode) {
            AuthMode.LEGACY -> when {
                sub == "discover" || p.str("encrypt_type") != null -> jo("error_code" to -40210)
                p.str("password") == Crypto.md5HexUpper(password) -> { loginCount++; stok = hex(16); jo("error_code" to 0, "result" to jo("stok" to stok)) }
                else -> jo("error_code" to -40401)
            }
            AuthMode.SECURE_V3 -> when {
                sub == "discover" -> jo("error_code" to -40413, "result" to jo("data" to jo("code" to -40413, "encrypt_type" to listOf("3"))))
                p.str("digest_passwd") != null -> {
                    val expected = Crypto.sha256HexUpper(storedHash + cnonce + nonce) + cnonce + nonce
                    if (p.str("digest_passwd") != expected || p.str("cnonce") != cnonce) jo("error_code" to -40401)
                    else {
                        loginCount++; stok = hex(16); seq = 100 + rnd.nextInt(1000)
                        keys = TapoClient.SecureV3Keys(storedHash, cnonce, nonce)
                        jo("error_code" to 0, "result" to jo("stok" to stok, "user_group" to "root", "start_seq" to seq))
                    }
                }
                p.str("cnonce") != null -> {
                    cnonce = p.str("cnonce")!!; nonce = hex(16)
                    val confirm = Crypto.sha256HexUpper(cnonce + storedHash + nonce) + nonce + cnonce
                    jo("error_code" to -40413, "result" to jo("data" to jo("code" to -40413, "encrypt_type" to listOf("3"), "nonce" to nonce, "device_confirm" to confirm)))
                }
                else -> jo("error_code" to -40413, "result" to jo("data" to jo("encrypt_type" to listOf("3"))))
            }
            AuthMode.TPAP -> when (sub) {
                "discover" -> jo("error_code" to 0, "result" to jo("tpap" to jo("pake" to listOf(2), "user_hash_type" to 0)))
                "pake_register" -> {
                    require(p.str("username") == Crypto.md5Hex("admin"))
                    userRandom = d64.decode(p.str("user_random"))
                    val salt = ByteArray(16).also { rnd.nextBytes(it) }
                    val devRandom = ByteArray(32).also { rnd.nextBytes(it) }
                    val credential = Sha256Crypt.crypt(Crypto.md5Hex(password), shadowPrefix)
                    verifier = FakeSpakeVerifier(credential, salt, 1000, devRandom)
                    jo("error_code" to 0, "result" to jo(
                        "dev_salt" to b64.encodeToString(salt), "iterations" to 1000,
                        "dev_share" to b64.encodeToString(verifier!!.devShare), "dev_random" to b64.encodeToString(devRandom),
                        "cipher_suites" to 1, "encryption" to "aes_128_ccm",
                        "extra_crypt" to jo("type" to "password_shadow", "params" to jo("passwd_id" to 5, "passwd_prefix" to shadowPrefix)),
                    ))
                }
                "pake_share" -> {
                    val userShare = d64.decode(p.str("user_share"))
                    val r = verifier!!.finish(userShare, userRandom)
                    if (!r.expectedUserConfirm.contentEquals(d64.decode(p.str("user_confirm")))) jo("error_code" to -40401)
                    else {
                        loginCount++; stok = hex(16); seq = rnd.nextInt(1_000_000); tpapKey = r.key; tpapNonce = r.nonce
                        jo("error_code" to 0, "result" to jo("dev_confirm" to b64.encodeToString(r.devConfirm), "stok" to stok, "start_seq" to seq, "expired" to 3600))
                    }
                }
                else -> jo("error_code" to -40211)
            }
        }
    }

    // ------------------------------------------------------------------ encrypted channels

    private fun secureDs(body: String, headers: Map<String, String>): HttpResult {
        val k = keys!!
        val reqSeq = headers["Seq"]!!.toInt()
        if (reqSeq != seq || headers["Tapo_tag"] != k.tag(body, reqSeq)) return json(jo("error_code" to -40401))
        seq++
        val enc = parseObject(body).str("params", "request")!!
        val inner = parseObject(String(Crypto.aesCbcDecrypt(k.lsk, k.ivb, d64.decode(enc))))
        val resp = handle(inner).toString().toByteArray()
        return json(jo("error_code" to 0, "result" to jo("response" to b64.encodeToString(Crypto.aesCbcEncrypt(k.lsk, k.ivb, resp)))))
    }

    private fun tpapDs(body: ByteArray): HttpResult {
        val reqSeq = ByteBuffer.wrap(body, 0, 4).int
        if (reqSeq != seq) return json(jo("error_code" to -40421))
        seq++
        val plain = Crypto.aesCcmDecrypt(tpapKey, TapoClient.tpapNonce(tpapNonce, reqSeq), body.copyOfRange(4, body.size))
        val inner = parseObject(String(plain))
        require(inner.str("method") == "multipleRequest") { "TPAP only takes multipleRequest" }
        val replySeq = rnd.nextInt()
        val out = TapoClient.seqBytes(replySeq) + Crypto.aesCcmEncrypt(tpapKey, TapoClient.tpapNonce(tpapNonce, replySeq), handle(inner).toString().toByteArray())
        return HttpResult(200, out)
    }

    // ------------------------------------------------------------------ device functions

    private fun handle(req: JSONObject): JSONObject {
        if (req.str("method") != "multipleRequest") return jo("error_code" to -40210)
        val list = req.at("params", "requests") as JSONArray
        return jo("error_code" to 0, "result" to jo("responses" to list.objects().map { one(it) }))
    }

    private fun ok(method: String, result: Any? = jo()) = jo("method" to method, "result" to result, "error_code" to 0)
    private fun err(method: String, code: Int) = jo("method" to method, "result" to jo(), "error_code" to code)

    private fun one(r: JSONObject): JSONObject {
        val m = r.str("method")!!
        calls += m
        val p = r.optJSONObject("params")
        return when (m) {
            "getDeviceInfo" -> ok(m, jo("device_info" to jo("basic_info" to jo("device_model" to "C210", "device_alias" to "Salon", "sw_version" to "1.4.6 Build 250101", "hw_version" to "2.0", "mac" to "AA-BB-CC-DD-EE-FF"))))
            "motorMove" -> if (state["privacy"] == "on") err(m, -64324) else {
                moves += p.str("motor", "move", "x_coord")!! to p.str("motor", "move", "y_coord")!!; ok(m)
            }
            "relativeMove" -> { moves += "step" to p.str("motor", "movestep", "direction")!!; ok(m) }
            "manualCalibrate" -> ok(m)
            "getLensMaskConfig" -> ok(m, jo("lens_mask" to jo("lens_mask_info" to jo("enabled" to state["privacy"]))))
            "setLensMaskConfig" -> { state["privacy"] = p.str("lens_mask", "lens_mask_info", "enabled")!!; ok(m) }
            "getLedStatus" -> ok(m, jo("led" to jo("config" to jo("enabled" to state["led"]))))
            "setLedStatus" -> { state["led"] = p.str("led", "config", "enabled")!!; ok(m) }
            "getDetectionConfig" -> ok(m, jo("motion_detection" to jo("motion_det" to jo("enabled" to state["motion"], "digital_sensitivity" to "50"))))
            "setDetectionConfig" -> { state["motion"] = p.str("motion_detection", "motion_det", "enabled")!!; ok(m) }
            "getTargetTrackConfig" -> ok(m, jo("target_track" to jo("target_track_info" to jo("enabled" to state["track"]))))
            "setTargetTrackConfig" -> { state["track"] = p.str("target_track", "target_track_info", "enabled")!!; ok(m) }
            "getNightVisionModeConfig" -> if (!supportsNewNightVision) err(m, -40210) else ok(m, jo("image" to jo("switch" to jo("night_vision_mode" to state["night"]))))
            "setNightVisionModeConfig" -> if (!supportsNewNightVision) err(m, -40210) else { state["night"] = p.str("image", "switch", "night_vision_mode")!!; ok(m) }
            "getDayNightModeConfig" -> ok(m, jo("image" to jo("common" to jo("inf_type" to "auto"))))
            "setDayNightModeConfig" -> { state["night_old"] = p.str("image", "common", "inf_type")!!; ok(m) }
            "getPresetConfig" -> ok(m, jo("preset" to jo("preset" to jo("id" to presets.map { it.first }, "name" to presets.map { it.second }))))
            "motorMoveToPreset" -> if (presets.any { it.first == p.str("preset", "goto_preset", "id") }) ok(m) else err(m, -64302)
            "addMotorPostion" -> { presets += (presets.size + 1).toString() to p.str("preset", "set_preset", "name")!!; ok(m) }
            "deletePreset" -> { val id = p.stringList("preset", "remove_preset", "id").first(); presets.removeAll { it.first == id }; ok(m) }
            "do" -> { alarm = r.str("msg_alarm", "manual_msg_alarm", "action")!!; jo("method" to "do", "error_code" to 0) }
            "rebootDevice" -> ok(m)
            else -> err(m, -40210)
        }
    }
}

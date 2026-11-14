package com.camctl.core

import org.json.JSONObject

/**
 * High-level commands. Method names and payloads are those the official app sends
 * (as documented by the open-source pytapo project), wrapped in multipleRequest.
 */
class TapoCamera(val client: TapoClient) {

    data class Info(val model: String, val name: String, val firmware: String, val hardware: String, val mac: String, val raw: JSONObject)
    data class Preset(val id: String, val name: String)
    enum class NightVision(val newApi: String, val oldApi: String, val label: String) {
        AUTO("md_night_vision", "auto", "Auto"),
        INFRARED("inf_night_vision", "on", "Infrarouge (N&B)"),
        DAY("wtl_night_vision", "off", "Jour / couleur"),
    }

    fun info(): Info {
        val r = client.call("getDeviceInfo", mapOf("device_info" to mapOf("name" to listOf("basic_info"))))
        val b = r.at("device_info", "basic_info") as? JSONObject ?: r
        return Info(
            model = b.str("device_model") ?: b.str("dev_model") ?: "?",
            name = b.str("device_alias") ?: b.str("device_name") ?: "?",
            firmware = b.str("sw_version") ?: "?",
            hardware = b.str("hw_version") ?: "?",
            mac = b.str("mac") ?: "?",
            raw = b,
        )
    }

    // ---- Pan / tilt
    /** Relative move in motor steps (about one degree each); x>0 right, y>0 up. */
    fun move(x: Int, y: Int) {
        client.call("motorMove", mapOf("motor" to mapOf("move" to mapOf("x_coord" to x.toString(), "y_coord" to y.toString()))))
    }

    /** Small step in a direction given as an angle: 0 right, 90 up, 180 left, 270 down. */
    fun step(angle: Int) {
        client.call("relativeMove", mapOf("motor" to mapOf("movestep" to mapOf("direction" to angle.toString()))))
    }

    fun calibrate() { client.call("manualCalibrate", mapOf("motor" to mapOf("manual_cali" to ""))) }

    // ---- Presets
    fun presets(): List<Preset> {
        val r = client.call("getPresetConfig", mapOf("preset" to mapOf("name" to listOf("preset"))))
        val ids = r.stringList("preset", "preset", "id")
        val names = r.stringList("preset", "preset", "name")
        return ids.mapIndexed { i, id -> Preset(id, names.getOrElse(i) { id }) }
    }

    fun gotoPreset(id: String) { client.call("motorMoveToPreset", mapOf("preset" to mapOf("goto_preset" to mapOf("id" to id)))) }
    fun savePreset(name: String) { client.call("addMotorPostion", mapOf("preset" to mapOf("set_preset" to mapOf("name" to name, "save_ptz" to "1")))) }
    fun deletePreset(id: String) { client.call("deletePreset", mapOf("preset" to mapOf("remove_preset" to mapOf("id" to listOf(id))))) }

    // ---- Switches
    fun privacy(): Boolean = client.call("getLensMaskConfig", mapOf("lens_mask" to mapOf("name" to listOf("lens_mask_info"))))
        .str("lens_mask", "lens_mask_info", "enabled") == "on"
    fun setPrivacy(on: Boolean) { client.call("setLensMaskConfig", mapOf("lens_mask" to mapOf("lens_mask_info" to mapOf("enabled" to onOff(on))))) }

    fun led(): Boolean = client.call("getLedStatus", mapOf("led" to mapOf("name" to listOf("config")))).str("led", "config", "enabled") == "on"
    fun setLed(on: Boolean) { client.call("setLedStatus", mapOf("led" to mapOf("config" to mapOf("enabled" to onOff(on))))) }

    fun motionDetection(): Boolean = client.call("getDetectionConfig", mapOf("motion_detection" to mapOf("name" to listOf("motion_det"))))
        .str("motion_detection", "motion_det", "enabled") == "on"
    fun setMotionDetection(on: Boolean) { client.call("setDetectionConfig", mapOf("motion_detection" to mapOf("motion_det" to mapOf("enabled" to onOff(on))))) }

    fun autoTrack(): Boolean = client.call("getTargetTrackConfig", mapOf("target_track" to mapOf("name" to listOf("target_track_info"))))
        .str("target_track", "target_track_info", "enabled") == "on"
    fun setAutoTrack(on: Boolean) { client.call("setTargetTrackConfig", mapOf("target_track" to mapOf("target_track_info" to mapOf("enabled" to onOff(on))))) }

    // ---- Night vision: newer firmware uses night_vision_mode, older uses inf_type.
    fun nightVision(): NightVision? {
        val v = runCatching {
            client.call("getNightVisionModeConfig", mapOf("image" to mapOf("name" to listOf("switch")))).str("image", "switch", "night_vision_mode")
        }.getOrNull()
        if (v != null) return NightVision.entries.firstOrNull { it.newApi == v }
        val old = client.call("getDayNightModeConfig", mapOf("image" to mapOf("name" to listOf("common")))).str("image", "common", "inf_type")
        return NightVision.entries.firstOrNull { it.oldApi == old }
    }

    fun setNightVision(mode: NightVision) {
        try {
            client.call("setNightVisionModeConfig", mapOf("image" to mapOf("switch" to mapOf("night_vision_mode" to mode.newApi))))
        } catch (e: TapoException) {
            if (e.code !in UNSUPPORTED) throw e
            client.call("setDayNightModeConfig", mapOf("image" to mapOf("common" to mapOf("inf_type" to mode.oldApi))))
        }
    }

    // ---- Siren / alarm (the camera's own siren and light)
    fun alarm(start: Boolean) {
        val r = client.multi(listOf(jo("method" to "do", "msg_alarm" to mapOf("manual_msg_alarm" to mapOf("action" to if (start) "start" else "stop"))))).first()
        if (r.errorCode() != 0) throw TapoException(r.errorCode(), "alarme: ${TapoErrors.describe(r.errorCode())}")
    }

    fun reboot() { client.call("rebootDevice", mapOf("system" to mapOf("reboot" to "null"))) }

    /** Tries every read-only getter to report what this model/firmware accepts. Changes nothing. */
    fun probeCapabilities(): List<Pair<String, String>> {
        val probes = listOf<Pair<String, () -> Any?>>(
            "Infos appareil" to { info().let { "${it.model} fw ${it.firmware}" } },
            "Mode privé" to { onOff(privacy()) },
            "LED" to { onOff(led()) },
            "Détection de mouvement" to { onOff(motionDetection()) },
            "Suivi auto" to { onOff(autoTrack()) },
            "Vision nocturne" to { nightVision()?.label },
            "Préréglages PTZ" to { "${presets().size} enregistrés" },
        )
        return probes.map { (name, f) ->
            name to try { "OK — ${f()}" } catch (e: Exception) { "Non disponible — ${e.message}" }
        }
    }

    private fun onOff(b: Boolean) = if (b) "on" else "off"

    companion object {
        val UNSUPPORTED = setOf(-40210, -40105, -40106, -40101)
    }
}

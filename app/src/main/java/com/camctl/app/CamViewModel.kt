package com.camctl.app

import android.app.Application
import android.net.Uri
import android.net.wifi.WifiManager
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.camctl.core.AuthMode
import com.camctl.core.Discovery
import com.camctl.core.FoundDevice
import com.camctl.core.TapoCamera
import com.camctl.core.TapoClient
import com.camctl.core.parseObject
import com.camctl.core.pretty
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class UiState(
    val screen: Screen = Screen.DISCOVER,
    val localIp: String? = null,
    val scanning: Boolean = false,
    val scanProgress: Int = 0,
    val devices: List<FoundDevice> = emptyList(),
    val host: String = "",
    val password: String = "",
    val rtspUser: String = "",
    val rtspPass: String = "",
    val connecting: Boolean = false,
    val busy: Boolean = false,
    val info: TapoCamera.Info? = null,
    val mode: AuthMode? = null,
    val privacy: Boolean? = null,
    val led: Boolean? = null,
    val motion: Boolean? = null,
    val track: Boolean? = null,
    val night: TapoCamera.NightVision? = null,
    val presets: List<TapoCamera.Preset> = emptyList(),
    val stepSize: Int = 15,
    val hd: Boolean = false,
    val capabilities: List<Pair<String, String>> = emptyList(),
    val consoleOutput: String = "",
    val log: List<String> = emptyList(),
    val toast: String? = null,
) {
    val rtspUrl: String?
        get() = if (rtspUser.isBlank() || host.isBlank()) null
        else "rtsp://${Uri.encode(rtspUser)}:${Uri.encode(rtspPass)}@$host:554/${if (hd) "stream1" else "stream2"}"
}

enum class Screen { DISCOVER, CONTROL }

@OptIn(ExperimentalCoroutinesApi::class)
class CamViewModel(app: Application) : AndroidViewModel(app) {
    private val store = SecureStore(app)
    private val _state = MutableStateFlow(
        UiState(
            host = store.get("host"),
            password = store.get("password"),
            rtspUser = store.get("rtspUser"),
            rtspPass = store.get("rtspPass"),
            localIp = NetInfo.localIpv4(app),
        )
    )
    val state: StateFlow<UiState> = _state

    /** One camera at a time; every call runs on this single background lane. */
    private val io = Dispatchers.IO.limitedParallelism(1)
    private var camera: TapoCamera? = null
    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.FRANCE)

    private fun log(msg: String) = _state.update { it.copy(log = (it.log + "${timeFmt.format(Date())}  $msg").takeLast(200)) }
    fun toast(msg: String?) = _state.update { it.copy(toast = msg) }

    fun edit(f: (UiState) -> UiState) = _state.update(f)

    // ------------------------------------------------------------ discovery

    fun scan() {
        if (_state.value.scanning) return
        val ip = NetInfo.localIpv4(getApplication())
        _state.update { it.copy(localIp = ip, scanning = true, scanProgress = 0, devices = emptyList()) }
        if (ip == null) { toast("Pas de réseau Wi-Fi détecté"); _state.update { it.copy(scanning = false) }; return }
        val prefix = ip.substringBeforeLast('.')
        viewModelScope.launch(Dispatchers.IO) {
            log("Recherche ONVIF (multicast) puis balayage de $prefix.1-254…")
            val wifi = getApplication<Application>().applicationContext.getSystemService(WifiManager::class.java)
            val lock = wifi?.createMulticastLock("camctl")?.apply { setReferenceCounted(false); acquire() }
            val onvif = try { Discovery.onvifProbe() } catch (e: Exception) { log("ONVIF: ${e.message}"); emptyList() } finally { lock?.release() }
            log("ONVIF: ${onvif.size} réponse(s)")
            _state.update { it.copy(devices = Discovery.merge(onvif, emptyList())) }
            val swept = Discovery.scanSubnet(prefix, onProgress = { n -> _state.update { it.copy(scanProgress = n) } })
            var all = Discovery.merge(onvif, swept)
            all = all.map { d -> if (d.looksLikeTapo && 443 in d.openPorts) d.copy(authHint = Discovery.identify(d.ip)) else d }
            log("Balayage terminé: ${all.size} hôte(s) avec un port caméra, ${all.count { it.looksLikeTapo }} probable(s) Tapo")
            _state.update { it.copy(devices = all, scanning = false) }
        }
    }

    // ------------------------------------------------------------ connection

    fun connect() {
        val s = _state.value
        if (s.host.isBlank() || s.password.isBlank()) { toast("Adresse IP et mot de passe requis"); return }
        store.put("host", s.host.trim()); store.put("password", s.password)
        store.put("rtspUser", s.rtspUser.trim()); store.put("rtspPass", s.rtspPass)
        _state.update { it.copy(connecting = true, host = s.host.trim()) }
        viewModelScope.launch(io) {
            try {
                val client = TapoClient(s.host.trim(), s.password, log = ::log)
                val cam = TapoCamera(client)
                val info = cam.info()
                camera = cam
                log("Connecté à ${info.name} (${info.model}, firmware ${info.firmware})")
                _state.update { it.copy(connecting = false, screen = Screen.CONTROL, info = info, mode = client.mode) }
                refreshInternal()
            } catch (e: Exception) {
                log("Échec de connexion: ${e.message}")
                _state.update { it.copy(connecting = false, toast = e.message ?: e.toString()) }
            }
        }
    }

    fun disconnect() {
        camera?.client?.logout(); camera = null
        _state.update { it.copy(screen = Screen.DISCOVER, info = null, capabilities = emptyList()) }
    }

    fun refresh() = run("Actualisation") { refreshInternal() }

    private fun refreshInternal() {
        val cam = camera ?: return
        fun <T> tryGet(name: String, f: () -> T): T? = try { f() } catch (e: Exception) { log("$name: ${e.message}"); null }
        val privacy = tryGet("Mode privé") { cam.privacy() }
        val led = tryGet("LED") { cam.led() }
        val motion = tryGet("Détection") { cam.motionDetection() }
        val track = tryGet("Suivi") { cam.autoTrack() }
        val night = tryGet("Vision nocturne") { cam.nightVision() }
        val presets = tryGet("Préréglages") { cam.presets() } ?: emptyList()
        _state.update { it.copy(privacy = privacy, led = led, motion = motion, track = track, night = night, presets = presets) }
    }

    /** Runs a camera command off the UI thread, logs it and surfaces errors. */
    private fun run(label: String, refreshAfter: Boolean = false, block: (TapoCamera) -> Unit) {
        val cam = camera ?: return
        _state.update { it.copy(busy = true) }
        viewModelScope.launch(io) {
            try {
                block(cam)
                log("$label: OK")
                if (refreshAfter) refreshInternal()
            } catch (e: Exception) {
                log("$label: ${e.message}")
                toast("$label: ${e.message}")
            } finally {
                _state.update { it.copy(busy = false) }
            }
        }
    }

    fun move(dx: Int, dy: Int) = run("Déplacement ($dx, $dy)") { it.move(dx, dy) }
    fun calibrate() = run("Calibrage") { it.calibrate() }
    fun setPrivacy(on: Boolean) = run("Mode privé ${onOff(on)}", true) { it.setPrivacy(on) }
    fun setLed(on: Boolean) = run("LED ${onOff(on)}", true) { it.setLed(on) }
    fun setMotion(on: Boolean) = run("Détection de mouvement ${onOff(on)}", true) { it.setMotionDetection(on) }
    fun setTrack(on: Boolean) = run("Suivi auto ${onOff(on)}", true) { it.setAutoTrack(on) }
    fun setNight(m: TapoCamera.NightVision) = run("Vision nocturne ${m.label}", true) { it.setNightVision(m) }
    fun alarm(start: Boolean) = run(if (start) "Sirène ON" else "Sirène OFF") { it.alarm(start) }
    fun gotoPreset(p: TapoCamera.Preset) = run("Aller à « ${p.name} »") { it.gotoPreset(p.id) }
    fun savePreset(name: String) = run("Enregistrer « $name »", true) { it.savePreset(name) }
    fun deletePreset(p: TapoCamera.Preset) = run("Supprimer « ${p.name} »", true) { it.deletePreset(p.id) }
    fun reboot() = run("Redémarrage") { it.reboot() }

    fun probe() = run("Diagnostic des fonctions") { cam ->
        val r = cam.probeCapabilities()
        _state.update { it.copy(capabilities = r) }
    }

    /** Raw console: sends {"method": method, "params": params} and shows the camera's answer. */
    fun console(method: String, params: String) = run("Console $method") { cam ->
        val p = if (params.isBlank()) null else parseObject(params)
        val r = cam.client.call(method.trim(), p)
        _state.update { it.copy(consoleOutput = r.pretty()) }
    }

    private fun onOff(b: Boolean) = if (b) "on" else "off"
}

package com.camctl.app

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.camctl.core.FoundDevice
import com.camctl.core.TapoCamera

class MainActivity : ComponentActivity() {
    private val vm: CamViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = Color(0xFF6EA8FE), secondary = Color(0xFF8BD3A5))) {
                Surface(Modifier.fillMaxSize(), color = Color(0xFF101418)) {
                    val s by vm.state.collectAsStateWithLifecycle()
                    val ctx = LocalContext.current
                    LaunchedEffect(s.toast) {
                        s.toast?.let { Toast.makeText(ctx, it, Toast.LENGTH_LONG).show(); vm.toast(null) }
                    }
                    when (s.screen) {
                        Screen.DISCOVER -> DiscoverScreen(s, vm)
                        Screen.CONTROL -> {
                            BackHandler { vm.disconnect() }
                            ControlScreen(s, vm)
                        }
                    }
                }
            }
        }
    }
}

// ============================================================== discovery + login

@Composable
fun DiscoverScreen(s: UiState, vm: CamViewModel) {
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("CamCtl", fontSize = 26.sp, fontWeight = FontWeight.Bold)
        Text("Contrôle local des caméras Tapo, sans cloud. Téléphone : ${s.localIp ?: "pas de Wi-Fi"}", color = Color.Gray, fontSize = 13.sp)

        Section("1 · Trouver la caméra") {
            Button(onClick = vm::scan, enabled = !s.scanning, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.Search, null); Spacer(Modifier.width(8.dp))
                Text(if (s.scanning) "Recherche… ${s.scanProgress}/254" else "Scanner le réseau local")
            }
            if (s.scanning) LinearProgressIndicator(progress = { s.scanProgress / 254f }, modifier = Modifier.fillMaxWidth())
            s.devices.forEach { d -> DeviceRow(d, selected = d.ip == s.host) { vm.edit { it.copy(host = d.ip) } } }
            if (!s.scanning && s.devices.isEmpty()) Text("Aucun résultat pour l'instant. Vous pouvez aussi saisir l'IP (visible dans l'appli Tapo ou votre box).", color = Color.Gray, fontSize = 13.sp)
        }

        Section("2 · Se connecter") {
            OutlinedTextField(s.host, { v -> vm.edit { it.copy(host = v) } }, label = { Text("Adresse IP de la caméra") },
                singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri), modifier = Modifier.fillMaxWidth())
            OutlinedTextField(s.password, { v -> vm.edit { it.copy(password = v) } }, label = { Text("Mot de passe du compte TP-Link") },
                singleLine = true, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
            Text("Pour la vidéo (facultatif) : le « Compte caméra » créé dans l'appli Tapo › Paramètres avancés.", color = Color.Gray, fontSize = 13.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(s.rtspUser, { v -> vm.edit { it.copy(rtspUser = v) } }, label = { Text("Utilisateur caméra") }, singleLine = true, modifier = Modifier.weight(1f))
                OutlinedTextField(s.rtspPass, { v -> vm.edit { it.copy(rtspPass = v) } }, label = { Text("Mot de passe caméra") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), modifier = Modifier.weight(1f))
            }
            Button(onClick = vm::connect, enabled = !s.connecting, modifier = Modifier.fillMaxWidth()) {
                if (s.connecting) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp) else Icon(Icons.Default.Login, null)
                Spacer(Modifier.width(8.dp)); Text("Se connecter")
            }
        }
        LogPanel(s.log)
    }
}

@Composable
fun DeviceRow(d: FoundDevice, selected: Boolean, onClick: () -> Unit) {
    val bg = if (selected) Color(0xFF22324A) else Color(0xFF1A2028)
    Row(
        Modifier.fillMaxWidth().background(bg, RoundedCornerShape(10.dp)).clickable(onClick = onClick).padding(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(if (d.looksLikeTapo) Icons.Default.Videocam else Icons.Default.DeviceUnknown, null, tint = if (d.looksLikeTapo) Color(0xFF8BD3A5) else Color.Gray)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(d.ip, fontWeight = FontWeight.SemiBold)
            Text(listOfNotNull(d.label, d.authHint).joinToString(" · "), fontSize = 12.sp, color = Color.LightGray)
            Text("Ports : ${d.openPorts.joinToString()}", fontSize = 12.sp, color = Color.Gray)
        }
        if (selected) Icon(Icons.Default.CheckCircle, null, tint = MaterialTheme.colorScheme.primary)
    }
}

// ============================================================== control

@Composable
fun ControlScreen(s: UiState, vm: CamViewModel) {
    var confirmReboot by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Row(Modifier.fillMaxWidth().padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = vm::disconnect) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Retour") }
            Column(Modifier.weight(1f)) {
                Text(s.info?.name ?: s.host, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                Text("${s.info?.model} · fw ${s.info?.firmware} · ${s.mode?.label}", fontSize = 11.sp, color = Color.Gray)
            }
            if (s.busy) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
            IconButton(onClick = vm::refresh) { Icon(Icons.Default.Refresh, "Actualiser") }
        }

        // Video
        Box(Modifier.fillMaxWidth().aspectRatio(16f / 9f).background(Color.Black), contentAlignment = Alignment.Center) {
            val url = s.rtspUrl
            if (url == null) Text("Vidéo : renseignez le compte caméra\nsur l'écran de connexion", color = Color.Gray, fontSize = 13.sp)
            else if (s.privacy == true) Text("Mode privé actif : objectif masqué", color = Color.Gray)
            else RtspPlayer(url, Modifier.fillMaxSize())
        }
        Row(Modifier.padding(horizontal = 16.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("Qualité", fontSize = 13.sp, color = Color.Gray); Spacer(Modifier.width(8.dp))
            FilterChip(!s.hd, { vm.edit { it.copy(hd = false) } }, { Text("SD") })
            Spacer(Modifier.width(6.dp))
            FilterChip(s.hd, { vm.edit { it.copy(hd = true) } }, { Text("HD") })
        }

        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Section("Orientation (pan / tilt)") {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    PtzPad(onMove = { dx, dy -> vm.move(dx * s.stepSize, dy * s.stepSize) })
                    Spacer(Modifier.width(16.dp))
                    Column {
                        Text("Pas : ${s.stepSize}°", fontSize = 13.sp)
                        Slider(s.stepSize.toFloat(), { v -> vm.edit { it.copy(stepSize = v.toInt()) } }, valueRange = 5f..60f, steps = 10, modifier = Modifier.width(150.dp))
                        OutlinedButton(onClick = vm::calibrate) { Text("Calibrer") }
                    }
                }
            }

            Section("Réglages") {
                Toggle("Mode privé (masque l'objectif)", Icons.Default.VisibilityOff, s.privacy, vm::setPrivacy)
                Toggle("Voyant LED", Icons.Default.Lightbulb, s.led, vm::setLed)
                Toggle("Détection de mouvement", Icons.Default.DirectionsRun, s.motion, vm::setMotion)
                Toggle("Suivi automatique", Icons.Default.CenterFocusStrong, s.track, vm::setTrack)
                Text("Vision nocturne", fontSize = 13.sp, color = Color.Gray)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    TapoCamera.NightVision.entries.forEach { m -> FilterChip(s.night == m, { vm.setNight(m) }, { Text(m.label, fontSize = 12.sp) }) }
                }
            }

            Section("Préréglages") {
                if (s.presets.isEmpty()) Text("Aucun préréglage (ou non supporté)", color = Color.Gray, fontSize = 13.sp)
                s.presets.forEach { p ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        TextButton(onClick = { vm.gotoPreset(p) }, modifier = Modifier.weight(1f)) { Icon(Icons.Default.Place, null); Spacer(Modifier.width(6.dp)); Text(p.name) }
                        IconButton(onClick = { vm.deletePreset(p) }) { Icon(Icons.Default.Delete, "Supprimer", tint = Color.Gray) }
                    }
                }
                var name by remember { mutableStateOf("") }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(name, { name = it }, label = { Text("Nom de la position actuelle") }, singleLine = true, modifier = Modifier.weight(1f))
                    IconButton(onClick = { if (name.isNotBlank()) { vm.savePreset(name.trim()); name = "" } }) { Icon(Icons.Default.Save, "Enregistrer") }
                }
            }

            Section("Sirène & système") {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { vm.alarm(true) }, colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFB3261E))) { Icon(Icons.Default.NotificationsActive, null); Spacer(Modifier.width(6.dp)); Text("Sirène") }
                    OutlinedButton(onClick = { vm.alarm(false) }) { Text("Arrêter") }
                    OutlinedButton(onClick = { confirmReboot = true }) { Text("Redémarrer") }
                }
            }

            Section("Diagnostic : que peut-on contrôler ?") {
                OutlinedButton(onClick = vm::probe) { Text("Tester les fonctions (lecture seule)") }
                s.capabilities.forEach { (name, res) ->
                    Text("• $name : $res", fontSize = 12.sp, color = if (res.startsWith("OK")) Color(0xFF8BD3A5) else Color(0xFFE8A0A0))
                }
            }

            ConsoleSection(s, vm)
            LogPanel(s.log)
        }
    }
    if (confirmReboot) AlertDialog(
        onDismissRequest = { confirmReboot = false },
        title = { Text("Redémarrer la caméra ?") },
        text = { Text("Elle sera hors ligne environ une minute.") },
        confirmButton = { TextButton({ confirmReboot = false; vm.reboot() }) { Text("Redémarrer") } },
        dismissButton = { TextButton({ confirmReboot = false }) { Text("Annuler") } },
    )
}

@Composable
fun PtzPad(onMove: (Int, Int) -> Unit) {
    @Composable
    fun B(icon: ImageVector, desc: String, dx: Int, dy: Int) =
        FilledTonalIconButton(onClick = { onMove(dx, dy) }, modifier = Modifier.size(52.dp)) { Icon(icon, desc) }
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        B(Icons.Default.KeyboardArrowUp, "Haut", 0, 1)
        Row {
            B(Icons.Default.KeyboardArrowLeft, "Gauche", -1, 0)
            Spacer(Modifier.size(52.dp))
            B(Icons.Default.KeyboardArrowRight, "Droite", 1, 0)
        }
        B(Icons.Default.KeyboardArrowDown, "Bas", 0, -1)
    }
}

@Composable
fun ConsoleSection(s: UiState, vm: CamViewModel) {
    var open by remember { mutableStateOf(false) }
    var method by remember { mutableStateOf("getDeviceInfo") }
    var params by remember { mutableStateOf("{\"device_info\":{\"name\":[\"basic_info\"]}}") }
    Section("Console brute (exploration du protocole)") {
        TextButton(onClick = { open = !open }) { Text(if (open) "Masquer" else "Afficher") }
        if (open) {
            Text("Envoie {method, params} dans un multipleRequest chiffré. Attention : les méthodes set*/do modifient la caméra.", fontSize = 12.sp, color = Color.Gray)
            OutlinedTextField(method, { method = it }, label = { Text("method") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(params, { params = it }, label = { Text("params (JSON)") }, textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 12.sp), modifier = Modifier.fillMaxWidth())
            Button(onClick = { vm.console(method, params) }) { Text("Envoyer") }
            if (s.consoleOutput.isNotEmpty()) Text(s.consoleOutput, fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                modifier = Modifier.fillMaxWidth().background(Color(0xFF0B0E12)).padding(8.dp))
        }
    }
}

@Composable
fun Toggle(label: String, icon: ImageVector, value: Boolean?, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, null, tint = Color.Gray); Spacer(Modifier.width(10.dp))
        Text(label, Modifier.weight(1f))
        if (value == null) Text("n/d", color = Color.Gray, fontSize = 12.sp)
        else Switch(value, onChange)
    }
}

@Composable
fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier.fillMaxWidth().background(Color(0xFF161B22), RoundedCornerShape(14.dp)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(title, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary)
        content()
    }
}

@Composable
fun LogPanel(log: List<String>) {
    if (log.isEmpty()) return
    Section("Journal") {
        Column(Modifier.heightIn(max = 220.dp).verticalScroll(rememberScrollState())) {
            log.takeLast(60).reversed().forEach { Text(it, fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = Color.LightGray) }
        }
    }
}

package com.camctl.app

import androidx.annotation.OptIn
import androidx.compose.foundation.layout.Box
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.media3.common.MediaItem
import androidx.media3.common.PlaybackException
import androidx.media3.common.Player
import androidx.media3.common.util.UnstableApi
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.exoplayer.rtsp.RtspMediaSource
import androidx.media3.ui.PlayerView

/**
 * Live view from the camera's RTSP server (port 554; stream1 = HD, stream2 = SD).
 * RTP over TCP is forced: more reliable over Wi-Fi than UDP.
 */
@OptIn(UnstableApi::class)
@Composable
fun RtspPlayer(url: String, modifier: Modifier = Modifier) {
    val ctx = LocalContext.current
    var error by remember(url) { mutableStateOf<String?>(null) }
    val player = remember(url) {
        ExoPlayer.Builder(ctx).build().apply {
            setMediaSource(RtspMediaSource.Factory().setForceUseRtpTcp(true).createMediaSource(MediaItem.fromUri(url)))
            addListener(object : Player.Listener {
                override fun onPlayerError(e: PlaybackException) {
                    error = "Vidéo indisponible : ${e.errorCodeName}\n(vérifiez le compte caméra)"
                }
            })
            playWhenReady = true
            prepare()
        }
    }
    DisposableEffect(player) { onDispose { player.release() } }
    Box(modifier, contentAlignment = Alignment.Center) {
        AndroidView(factory = { PlayerView(it).apply { useController = false; this.player = player } }, update = { it.player = player }, modifier = modifier)
        error?.let { Text(it, color = Color.White) }
    }
}

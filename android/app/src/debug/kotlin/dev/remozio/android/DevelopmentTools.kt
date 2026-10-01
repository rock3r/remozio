package dev.remozio.android

import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import dev.remozio.android.requests.CommandInspection
import dev.remozio.protocol.CborLimits
import dev.remozio.protocol.CommandCapture

@Composable
internal fun DevelopmentTools() {
    var showing by remember { mutableStateOf(false) }
    OutlinedButton(onClick = { showing = true }) { Text(stringResource(R.string.open_sample_command)) }
    if (showing) {
        val resources = LocalResources.current
        val capture = remember(resources) {
            val bytes = resources.openRawResource(R.raw.sample_command).use { it.readBytes() }
            CommandCapture(bytes, CborLimits(8192, 16, 1024))
        }
        CommandInspection(capture, stringResource(R.string.sample_mac), stringResource(R.string.sample_account),
            onDismiss = { showing = false }, sample = true)
    }
}

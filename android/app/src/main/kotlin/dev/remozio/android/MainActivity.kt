package dev.remozio.android

import android.os.Bundle
import dev.remozio.android.audit.AuditScreen
import dev.remozio.android.push.NotificationSettingsScreen
import dev.remozio.android.enrollment.StoredMacList
import dev.remozio.android.updates.UpdateStatusCard
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialExpressiveTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Text
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { RemozioTheme { RemozioScreen() } }
    }
}

@Composable
internal fun RemozioTheme(content: @Composable () -> Unit) {
    val context = LocalContext.current
    val colors = if (isSystemInDarkTheme()) {
        dynamicDarkColorScheme(context)
    } else {
        dynamicLightColorScheme(context)
    }
    MaterialExpressiveTheme(colorScheme = colors, content = content)
}

@Composable
private fun RemozioScreen() {
    var destination by rememberSaveable { mutableIntStateOf(0) }
    val labels = listOf(R.string.nav_macs, R.string.nav_audit, R.string.nav_settings)
    val icons = listOf(R.drawable.ic_macs, R.drawable.ic_audit, R.drawable.ic_settings)
    BoxWithConstraints(Modifier.fillMaxSize()) {
        val expanded = maxWidth >= 600.dp
        Scaffold(bottomBar = {
            if (!expanded) NavigationBar {
                labels.indices.forEach { index -> NavigationBarItem(
                    selected = destination == index, onClick = { destination = index },
                    icon = { Icon(painterResource(icons[index]), contentDescription = null) },
                    label = { Text(stringResource(labels[index])) },
                ) }
            }
        }) { insets ->
            Row(Modifier.fillMaxSize().padding(insets)) {
                if (expanded) NavigationRail {
                    labels.indices.forEach { index -> NavigationRailItem(
                        selected = destination == index, onClick = { destination = index },
                        icon = { Icon(painterResource(icons[index]), contentDescription = null) },
                        label = { Text(stringResource(labels[index])) },
                    ) }
                }
                Box(Modifier.weight(1f)) {
                    when (destination) { 1 -> AuditScreen(); 2 -> NotificationSettingsScreen(); else -> MacsScreen() }
                }
            }
        }
    }
}

@Composable
private fun MacsScreen() {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(Modifier.widthIn(max = 720.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(24.dp)) {
            Text(stringResource(R.string.your_macs), style = MaterialTheme.typography.headlineLarge,
                modifier = Modifier.semantics { heading() })
            StoredMacList()
            UpdateStatusCard()
            DevelopmentTools()
        }
    }
}

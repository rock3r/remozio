package dev.sebastiano.remozio.android.enrollment

import android.Manifest
import android.os.SystemClock
import android.content.pm.PackageManager
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.DialogWindowProvider
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import java.util.concurrent.atomic.AtomicBoolean
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import dev.remozio.protocol.PairingInvitation
import dev.remozio.protocol.PairingInvitationV2
import dev.remozio.protocol.RePairInvitation
import dev.sebastiano.remozio.android.R
import dev.sebastiano.remozio.android.biometrics.AndroidPairingBiometrics
import dev.sebastiano.remozio.android.biometrics.PairingBiometricPrompt
import dev.sebastiano.remozio.android.biometrics.PairingBiometricResult
import kotlinx.coroutines.delay

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun PairingSetupSheet(model: PairingViewModel, activity: ComponentActivity, testV2: Boolean = false) {
    val state by model.state.collectAsState()
    if (state.phase == PairingPhase.CLOSED) return
    val lifecycle = activity.lifecycle
    DisposableEffect(lifecycle, model) {
        val observer = object : DefaultLifecycleObserver {
            override fun onResume(owner: LifecycleOwner) = model.foreground(true)
            override fun onPause(owner: LifecycleOwner) = model.foreground(false)
        }
        lifecycle.addObserver(observer)
        model.foreground(lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED))
        onDispose { lifecycle.removeObserver(observer); model.foreground(false) }
    }
    PairingSetupSurface(state, model::connect, model::confirmComparison, model::expire, model::close,
        inspectRePair = model::inspectRePair, onConnectV2 = { model.connectV2(it, offerDecisionProof = !testV2) },
        inspectRePairV2 = model::inspectRePairV2, legacyInputEnabled = !testV2,
        biometrics = PairingBiometricHost(activity, model::biometricResult))
}

internal class PairingBiometricHost(
    val activity: ComponentActivity,
    val onResult: (AndroidPairingBiometrics, PairingBiometricResult) -> Unit,
)

/** The retained setup host owns the attempt. The active comparison window owns its prompt. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun PairingSetupSurface(state: PairingScreenState, onConnect: (String) -> Boolean, onCompare: () -> Unit,
    onExpire: () -> Unit, onClose: () -> Unit, preview: Boolean = false,
    inspectRePair: (suspend (String) -> RePairAvailability)? = null,
    onConnectV2: ((PairingInvitationV2) -> Boolean)? = null,
    inspectRePairV2: (suspend (PairingInvitationV2) -> RePairAvailability)? = null,
    legacyInputEnabled: Boolean = true,
    biometrics: PairingBiometricHost? = null,
) {
    var seconds by remember(state.transcript) { mutableLongStateOf(0) }
    val expire by rememberUpdatedState(onExpire)
    LaunchedEffect(state.expiresElapsedMillis, state.phase) {
        val deadline = state.expiresElapsedMillis ?: return@LaunchedEffect
        while (true) {
            val remaining = (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0)
            seconds = (remaining + 999) / 1000
            if (seconds == 0L) { expire(); break }
            delay(1000)
        }
    }
    val needsProtection = requiresPairingWindowProtection(state.phase, preview)
    val capturePolicy = if (needsProtection) SecureFlagPolicy.SecureOn else SecureFlagPolicy.Inherit
    val timedContent: @Composable (Modifier) -> Unit = { modifier ->
        PairingComparisonWindow(needsProtection) { protection ->
            val hasCode = !state.comparisonCode.isNullOrEmpty()
            when (protection?.state) {
                PairingWindowProtection.State.CHECKING -> Unit
                PairingWindowProtection.State.UNAVAILABLE -> {
                    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        Text(stringResource(R.string.pairing_setup_protection_unavailable))
                        TextButton(onClick = onClose) { Text(stringResource(R.string.pairing_biometric_cancel)) }
                    }
                    val signer = state.signer
                    if (state.phase == PairingPhase.BIOMETRIC && signer != null && biometrics != null) {
                        LaunchedEffect(protection, signer) { biometrics.onResult(signer, PairingBiometricResult.Unavailable) }
                    }
                }
                PairingWindowProtection.State.READY, null -> {
                    val canMatch = hasCode && (preview || protection?.canMatch(state.phase, hasCode) == true)
                    PairingSetupContent(state, onConnect, onCompare = {
                        if (preview || protection?.canMatch(state.phase, hasCode) == true) onCompare()
                    }, canMatch = canMatch, seconds = seconds, onClose = onClose, preview = preview, modifier = modifier,
                        inspectRePair = inspectRePair, onConnectV2 = onConnectV2, inspectRePairV2 = inspectRePairV2,
                        legacyInputEnabled = legacyInputEnabled)
                    if (protection != null && biometrics != null && state.phase == PairingPhase.BIOMETRIC) {
                        PairingBiometricEffect(state, protection, biometrics)
                    }
                }
            }
        }
    }
    BoxWithConstraints {
        // Keep capture protection on the old window until Compose removes it and its content.
        key(needsProtection) {
            if (maxWidth >= 600.dp) {
                Dialog(onDismissRequest = onClose,
                    properties = DialogProperties(securePolicy = capturePolicy, usePlatformDefaultWidth = false)) {
                    Surface(Modifier.widthIn(max = 560.dp).fillMaxWidth().padding(24.dp), shape = MaterialTheme.shapes.extraLarge) {
                        timedContent(Modifier.padding(24.dp))
                    }
                }
            } else {
                ModalBottomSheet(onDismissRequest = onClose,
                    sheetState = rememberBottomSheetState(initialValue = SheetValue.Hidden,
                        enabledValues = setOf(SheetValue.Hidden, SheetValue.Expanded)),
                    properties = ModalBottomSheetProperties(securePolicy = capturePolicy)) {
                    timedContent(Modifier.padding(horizontal = 24.dp).padding(bottom = 24.dp))
                }
            }
        }
    }
}

@Composable
private fun PairingComparisonWindow(required: Boolean, content: @Composable (PairingWindowProtection?) -> Unit) {
    if (!required) {
        content(null)
        return
    }
    val window = generateSequence(LocalView.current.parent) { it.parent }
        .filterIsInstance<DialogWindowProvider>().firstOrNull()?.window
    key(window) {
        val protection = remember { PairingWindowProtection() }
        DisposableEffect(protection) {
            val secure = window != null && (window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
            protection.protect(secure) { checkNotNull(window).setHideOverlayWindows(true) }
            onDispose { protection.revoke() }
        }
        content(protection)
    }
}

@Composable
private fun PairingBiometricEffect(state: PairingScreenState, protection: PairingWindowProtection, host: PairingBiometricHost) {
    val signer = state.signer ?: return
    val onResult by rememberUpdatedState(host.onResult)
    val hasCode = !state.comparisonCode.isNullOrEmpty()
    DisposableEffect(protection, host.activity, signer, hasCode) {
        val prompt = protection.startBiometrics(state.phase, hasCode, signer) { current ->
            PairingBiometricPrompt(host.activity, current).apply {
                authenticate { result ->
                    val checked = if (result is PairingBiometricResult.Signed && protection.state != PairingWindowProtection.State.READY) {
                        PairingBiometricResult.Unavailable
                    } else result
                    onResult(current, checked)
                }
            }
        }
        onDispose { prompt?.close() }
    }
}

@Composable
private fun PairingSetupContent(state: PairingScreenState, onConnect: (String) -> Boolean, onCompare: () -> Unit,
    canMatch: Boolean, seconds: Long, onClose: () -> Unit, preview: Boolean, modifier: Modifier,
    inspectRePair: (suspend (String) -> RePairAvailability)?,
    onConnectV2: ((PairingInvitationV2) -> Boolean)?,
    inspectRePairV2: (suspend (PairingInvitationV2) -> RePairAvailability)?,
    legacyInputEnabled: Boolean,
) {
    val context = LocalContext.current
    var invitation by remember { mutableStateOf("") }
    var invitationV2 by remember { mutableStateOf<PairingInvitationV2?>(null) }
    LaunchedEffect(invitationV2) {
        val parsed = invitationV2 ?: return@LaunchedEffect
        delay(parsed.lifetimeMilliseconds.toLong())
        if (invitationV2 === parsed) invitationV2 = null
    }
    val input = invitation.trim()
    val isV1RePair = input.startsWith("remozio-repair:")
    val isV2RePair = invitationV2?.replacement != null
    val usesV2 = invitationV2 != null && onConnectV2 != null
    val rePairInput = if (usesV2) isV2RePair else isV1RePair
    var v1Availability by remember(input) { mutableStateOf<RePairAvailability?>(null) }
    var v2Availability by remember(invitationV2) { mutableStateOf<RePairAvailability?>(null) }
    val availability = if (usesV2) v2Availability else v1Availability
    val hasInvitation = usesV2 || (legacyInputEnabled && input.isNotBlank())
    val recovery = state.recoveryRecordID != null
    val canConnect = hasInvitation && (!recovery || rePairInput) &&
        (!rePairInput || availability == RePairAvailability.ELIGIBLE)

    fun connect() {
        if (!canConnect) return
        val parsed = invitationV2
        if (parsed != null && onConnectV2 != null) {
            if (onConnectV2(parsed)) invitationV2 = null
        } else if (legacyInputEnabled && onConnect(invitation)) {
            invitation = ""
        }
    }
    LaunchedEffect(input, state.phase, preview, inspectRePair) {
        if (isV1RePair && state.phase == PairingPhase.INPUT && !preview && inspectRePair != null) {
            delay(250)
            v1Availability = inspectRePair(input)
        }
    }
    LaunchedEffect(invitationV2, state.phase, preview, inspectRePairV2) {
        val parsed = invitationV2 ?: return@LaunchedEffect
        if (parsed.replacement != null && state.phase == PairingPhase.INPUT && !preview && inspectRePairV2 != null) {
            v2Availability = inspectRePairV2(parsed)
        }
    }
    var denied by remember { mutableStateOf(false) }
    var scannerBusy by remember { mutableStateOf(false) }
    var scannerFailed by remember { mutableStateOf(false) }
    var wrongInvitationVersion by remember { mutableStateOf(false) }
    val scannerLive = remember { AtomicBoolean(true) }
    DisposableEffect(Unit) { onDispose { scannerLive.set(false) } }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        denied = !granted
        if (granted && canConnect) connect()
    }
    Column(modifier.fillMaxWidth().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        if (preview) Text(stringResource(R.string.pairing_setup_preview), color = MaterialTheme.colorScheme.error)
        Text(stringResource(R.string.pairing_setup_title), style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.semantics { heading() })
        if (state.phase == PairingPhase.INPUT) {
            Text(stringResource(if (recovery) R.string.pairing_certificate_recovery_intro else R.string.pairing_setup_intro))
            OutlinedButton(onClick = {
                scannerBusy = true; scannerFailed = false; wrongInvitationVersion = false
                try {
                    val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).enableAutoZoom().build()
                    GmsBarcodeScanning.getClient(context, options).startScan()
                        .addOnSuccessListener { barcode ->
                            if (scannerLive.get()) {
                                val text = barcode.rawValue
                                invitation = ""
                                invitationV2 = null
                                if (text?.trimStart()?.startsWith("remozio-pairing:v2:") == true) {
                                    if (onConnectV2 == null) wrongInvitationVersion = true
                                    else {
                                        invitationV2 = runCatching { PairingInvitationV2.importText(text.trim()) }.getOrNull()
                                        scannerFailed = invitationV2 == null
                                    }
                                } else if (legacyInputEnabled && text != null && isLegacyPairingInvitation(text.trim())) {
                                    invitation = text.trim()
                                } else scannerFailed = true
                            }
                        }
                        .addOnFailureListener { if (scannerLive.get()) scannerFailed = true }
                        .addOnCompleteListener { if (scannerLive.get()) scannerBusy = false }
                } catch (_: RuntimeException) { scannerBusy = false; scannerFailed = true }
            }, enabled = !preview && !scannerBusy, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.pairing_setup_scan)) }
            if (scannerBusy) LinearProgressIndicator(Modifier.fillMaxWidth())
            if (scannerFailed) Text(stringResource(R.string.pairing_setup_scan_failed), color = MaterialTheme.colorScheme.error)
            if (wrongInvitationVersion) {
                Text(stringResource(R.string.pairing_setup_v2_wrong_field), color = MaterialTheme.colorScheme.error)
            }
            if (onConnectV2 != null) {
                AndroidView(factory = { viewContext ->
                    val acceptLegacy: ((String) -> Unit)? = if (legacyInputEnabled) {
                        { text -> invitationV2 = null; invitation = text }
                    } else null
                    PairingInvitationV2Editor(viewContext, onLegacyInvitation = acceptLegacy) { parsed ->
                        invitation = ""
                        invitationV2 = parsed
                    }
                }, modifier = Modifier.fillMaxWidth())
                if (hasInvitation) Text(stringResource(R.string.pairing_setup_invitation_ready))
            } else {
                OutlinedTextField(value = invitation, onValueChange = { text ->
                    val v2 = text.trimStart().startsWith("remozio-pairing:v2:")
                    wrongInvitationVersion = v2
                    scannerFailed = false
                    if (v2) invitation = ""
                    else if (text.length <= 16_384) invitation = text
                }, label = { Text(stringResource(R.string.pairing_setup_invitation)) },
                    modifier = Modifier.fillMaxWidth(), maxLines = 5)
            }
            if (denied) Text(stringResource(R.string.pairing_setup_lan_denied), color = MaterialTheme.colorScheme.error)
            when (availability) {
                RePairAvailability.PENDING -> Text(stringResource(R.string.pairing_repair_pending))
                RePairAvailability.UNAVAILABLE -> Text(stringResource(R.string.pairing_repair_unavailable))
                else -> Unit
            }
            if (!rePairInput || availability == RePairAvailability.ELIGIBLE) Button(onClick = {
                if (context.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED) connect()
                else permission.launch(Manifest.permission.ACCESS_LOCAL_NETWORK)
            }, enabled = !preview && canConnect, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(if (rePairInput) R.string.pairing_repair_connect else R.string.pairing_setup_connect))
            }
        } else {
            val status = when (state.phase) {
                PairingPhase.CONNECTING -> R.string.pairing_setup_waiting
                PairingPhase.COMPARING -> R.string.pairing_setup_compare
                PairingPhase.PREPARING, PairingPhase.BIOMETRIC -> R.string.pairing_setup_preparing
                PairingPhase.SUBMITTING -> R.string.pairing_setup_submitting
                PairingPhase.COMPLETE -> R.string.pairing_setup_complete
                PairingPhase.RECOVERY_PENDING -> R.string.pairing_repair_pending
                PairingPhase.EXPIRED -> R.string.pairing_setup_expired
                PairingPhase.CLOSING -> R.string.pairing_setup_closing
                else -> if (state.mayHaveSavedSetup) R.string.pairing_setup_incomplete else R.string.pairing_setup_failed
            }
            Text(stringResource(status), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            if (state.phase == PairingPhase.RE_PAIR_FAILED && !state.mayHaveSavedSetup) {
                Text(stringResource(R.string.pairing_repair_new_pairing_guidance))
            }
            if (state.phase in setOf(PairingPhase.CONNECTING, PairingPhase.PREPARING, PairingPhase.BIOMETRIC, PairingPhase.SUBMITTING, PairingPhase.CLOSING)) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
            }
            if (state.phase == PairingPhase.CONNECTING) {
                SelectionContainer { Text(stringResource(R.string.pairing_setup_phone, state.phoneSuffix), style = MaterialTheme.typography.titleMedium) }
            }
            state.comparisonCode?.let { code ->
                if (state.phase.displaysComparison) {
                    if (state.clockSkewAdvisory) Text(stringResource(R.string.pairing_setup_clock_advisory))
                    SelectionContainer {
                        Text(code.replace(" ", "\n"),
                            style = MaterialTheme.typography.headlineLarge, fontFamily = FontFamily.Monospace)
                    }
                    Text(pluralStringResource(R.plurals.pairing_setup_remaining, seconds.toInt(), seconds))
                }
            }
            if (state.phase == PairingPhase.COMPARING) {
                Button(onClick = onCompare, enabled = canMatch, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.pairing_setup_match)) }
                OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.pairing_setup_mismatch)) }
            }
        }
        if (state.phase != PairingPhase.COMPARING) TextButton(onClick = onClose,
            enabled = state.phase != PairingPhase.CLOSING) {
            Text(stringResource(if (state.phase == PairingPhase.COMPLETE) R.string.pairing_setup_done else R.string.pairing_biometric_cancel))
        }
    }
}

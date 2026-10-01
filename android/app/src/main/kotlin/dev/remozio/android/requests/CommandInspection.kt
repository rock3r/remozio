package dev.remozio.android.requests

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.SheetValue
import androidx.compose.material3.rememberBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import dev.remozio.android.R
import dev.remozio.protocol.AncestryCompleteness
import dev.remozio.protocol.AncestryReason
import dev.remozio.protocol.CapturedFileIdentity
import dev.remozio.protocol.CapturedSigningStatus
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.CommandCapture
import dev.remozio.protocol.CommandIOMode
import dev.remozio.protocol.CommandInputKind
import dev.remozio.protocol.EnvironmentSource
import dev.remozio.protocol.StartedCommandDisconnect

/** Inspection only. The caller must authenticate a live request before adding decision controls. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun CommandInspection(
    capture: CommandCapture?,
    macName: String,
    accountName: String,
    onDismiss: () -> Unit,
    sample: Boolean = false,
    status: TrackedRequestStatus? = null,
    requestKey: Any? = null,
) {
    val pixels = LocalWindowInfo.current.containerSize
    val window = with(LocalDensity.current) { pixels.width.toDp() to pixels.height.toDp() }
    val identity = status?.status?.let { listOf(it.macID, it.accountID, it.requestID, it.requestDigest, it.challenge).map(CborValue::Bytes) }
    val visibleCapture = if (status?.status?.phase?.isTerminal == true) null else capture
    key(requestKey ?: identity ?: capture) {
        if (window.first < 600.dp) {
            ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberBottomSheetState(
                initialValue = SheetValue.Hidden, enabledValues = setOf(SheetValue.Hidden, SheetValue.Expanded),
            )) {
                InspectionContent(visibleCapture, macName, accountName, sample, onDismiss, status, Modifier.heightIn(max = window.second * 0.9f))
            }
        } else {
            Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
                Surface(
                    modifier = Modifier.padding(24.dp).widthIn(max = 720.dp).fillMaxWidth().heightIn(max = window.second * 0.9f),
                    shape = MaterialTheme.shapes.extraLarge,
                ) { InspectionContent(visibleCapture, macName, accountName, sample, onDismiss, status) }
            }
        }
    }
}

@Composable
private fun InspectionContent(
    capture: CommandCapture?, macName: String, accountName: String, sample: Boolean, onDismiss: () -> Unit,
    status: TrackedRequestStatus?,
    modifier: Modifier = Modifier,
) {
    var raw by remember { mutableStateOf(false) }
    Column(modifier.fillMaxWidth()) {
        Column(Modifier.padding(horizontal = 24.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(when {
                sample && capture == null -> R.string.sample_status_title
                sample -> R.string.sample_command_title
                capture == null -> R.string.request_status_title
                else -> R.string.command_details
            }),
                style = MaterialTheme.typography.headlineSmall, modifier = Modifier.semantics { heading() })
            if (sample) Text(stringResource(R.string.sample_command_notice), style = MaterialTheme.typography.bodyMedium)
            if (capture != null) TextButton(onClick = { raw = !raw }) {
                Text(stringResource(if (raw) R.string.hide_exact_bytes else R.string.show_exact_bytes))
            }
        }
        LazyColumn(Modifier.weight(1f, fill = false), contentPadding = PaddingValues(horizontal = 24.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (status != null) item { RequestStatusCard(status) }
            item {
                Section(R.string.request_context) {
                    TextValue(R.string.mac_label, macName, raw)
                    TextValue(R.string.account_label, accountName, raw)
                }
            }
            if (capture == null) item {
                Text(stringResource(if (status?.status?.phase?.isTerminal == true) R.string.status_details_removed else R.string.status_details_unavailable))
            }
            else {
                item {
                    Section(R.string.invocation) {
                        BytesValue(R.string.executable_label, capture.executable.path, raw)
                        BytesValue(R.string.directory_label, capture.directory.path, raw)
                        Text(stringResource(R.string.display_not_shell), style = MaterialTheme.typography.bodySmall)
                    }
                }
                itemsIndexed(capture.arguments) { index, argument ->
                    Card(Modifier.fillMaxWidth()) {
                        Value(stringResource(R.string.argument_index, index), argument.copyBytes(), raw, Modifier.padding(16.dp))
                    }
                }
                item {
                    Section(R.string.target_credentials) {
                        Numeric(R.string.uid_label, capture.target.uid.toString())
                        Numeric(R.string.gid_label, capture.target.gid.toString())
                        Numeric(R.string.groups_label, capture.target.supplementaryGroups.joinToString(", ").ifEmpty { stringResource(R.string.none_label) })
                        TextValue(R.string.user_name_label, capture.target.observedName, raw)
                    }
                }
                item { Heading(R.string.effective_environment) }
                if (capture.environment.isEmpty()) item { Text(stringResource(R.string.empty_environment)) }
                itemsIndexed(capture.environment) { index, entry ->
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(stringResource(R.string.environment_index, index + 1), style = MaterialTheme.typography.titleSmall)
                            BytesValue(R.string.name_label, entry.name, raw)
                            BytesValue(R.string.value_label, entry.value, raw)
                            Text(stringResource(if (entry.source == EnvironmentSource.MINIMAL) R.string.minimal_environment else R.string.requested_environment),
                                style = MaterialTheme.typography.labelLarge)
                        }
                    }
                }
                item {
                    Section(R.string.input_and_lifetime) {
                        Text(stringResource(when (capture.input.kind) {
                            CommandInputKind.NULL -> R.string.input_null
                            CommandInputKind.PIPE -> R.string.input_pipe
                            CommandInputKind.FILE -> R.string.input_file
                            CommandInputKind.TTY -> R.string.input_tty
                            CommandInputKind.PTY -> R.string.input_pty
                        }))
                        if (capture.input.kind != CommandInputKind.NULL) Text(stringResource(R.string.input_not_captured))
                        BytesValue(R.string.input_path, capture.input.observedPath, raw)
                        Text(stringResource(if (capture.ioMode == CommandIOMode.PTY) R.string.io_pty else R.string.io_pipes))
                        Text(stringResource(if (capture.disconnectBehavior == StartedCommandDisconnect.TERMINATE) R.string.disconnect_terminate else R.string.disconnect_continue))
                    }
                }
                item {
                    Section(R.string.requester) {
                        BytesValue(R.string.requester_executable, capture.requester.executablePath, raw)
                        Numeric(R.string.real_uid, capture.requester.realUID.toString())
                        Numeric(R.string.effective_uid, capture.requester.effectiveUID.toString())
                        Numeric(R.string.pid_label, capture.requester.pid.toString())
                        Numeric(R.string.pid_version, capture.requester.pidVersion.toString())
                        Text(stringResource(when (capture.requester.signing.status) {
                            CapturedSigningStatus.UNSIGNED -> R.string.signing_unsigned
                            CapturedSigningStatus.AD_HOC -> R.string.signing_ad_hoc
                            CapturedSigningStatus.VALIDATED -> R.string.signing_validated
                            CapturedSigningStatus.INVALID -> R.string.signing_invalid
                            CapturedSigningStatus.UNAVAILABLE -> R.string.signing_unavailable
                        }), style = MaterialTheme.typography.titleSmall)
                        TextValue(R.string.signing_identifier, capture.requester.signing.identifier, raw)
                        TextValue(R.string.signing_team, capture.requester.signing.team, raw)
                        Numeric(R.string.session_id, capture.requester.sessionID?.toString())
                        BytesValue(R.string.tty_path, capture.requester.ttyPath, raw)
                    }
                }
                item {
                    Section(R.string.process_ancestry) {
                        Text(stringResource(when (capture.ancestry.completeness) {
                            AncestryCompleteness.COMPLETE -> R.string.ancestry_complete
                            AncestryCompleteness.PARTIAL -> R.string.ancestry_partial
                            AncestryCompleteness.UNAVAILABLE -> R.string.ancestry_unavailable
                        }))
                        if (capture.ancestry.reason != AncestryReason.NONE) Text(stringResource(when (capture.ancestry.reason) {
                            AncestryReason.EXITED -> R.string.ancestry_exited
                            AncestryReason.PERMISSION -> R.string.ancestry_permission
                            AncestryReason.TRUNCATED -> R.string.ancestry_truncated
                            AncestryReason.UNSUPPORTED -> R.string.ancestry_unsupported
                            AncestryReason.NONE -> R.string.none_label
                        }))
                        Text(stringResource(R.string.ancestry_identity_limit), style = MaterialTheme.typography.bodySmall)
                    }
                }
                itemsIndexed(capture.ancestry.entries) { index, ancestor ->
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(stringResource(R.string.ancestor_index, index + 1), style = MaterialTheme.typography.titleSmall)
                            BytesValue(R.string.requester_executable, ancestor.executablePath, raw)
                            Numeric(R.string.pid_label, ancestor.pid.toString())
                            Numeric(R.string.pid_version, ancestor.pidVersion.toString())
                            Numeric(R.string.uid_label, ancestor.uid.toString())
                        }
                    }
                }
                if (capture.unverifiedRationale != null) item {
                    Section(R.string.unverified_rationale) { TextValue(R.string.caller_explanation, capture.unverifiedRationale, raw) }
                }
                item {
                    Section(R.string.binding_details) {
                        Identity(R.string.executable_identity, capture.executable.identity)
                        Numeric(R.string.executable_sha256, ByteText.hex(capture.executable.sha256.copyBytes()))
                        Identity(R.string.directory_identity, capture.directory.identity)
                        Identity(R.string.input_identity, capture.input.identity)
                        Numeric(R.string.input_binding, capture.input.streamBinding?.copyBytes()?.let(ByteText::hex))
                        Numeric(R.string.code_directory_hash, capture.requester.signing.cdHash?.copyBytes()?.let(ByteText::hex))
                        Numeric(R.string.submission_id, ByteText.hex(capture.submission.id.copyBytes()))
                        Numeric(R.string.submission_nonce, ByteText.hex(capture.submission.nonce.copyBytes()))
                        Numeric(R.string.caller_binding, ByteText.hex(capture.submission.callerBinding.copyBytes()))
                    }
                }
            }
        }
        TextButton(onClick = onDismiss, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
            Text(stringResource(R.string.close_details))
        }
    }
}

@Composable
private fun Heading(title: Int) {
    Text(stringResource(title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
}
@Composable
private fun Section(title: Int, content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Heading(title)
            content()
        }
    }
}
@Composable
private fun BytesValue(label: Int, value: CborValue.Bytes?, raw: Boolean) = Value(stringResource(label), value?.copyBytes(), raw)
@Composable
private fun TextValue(label: Int, value: String?, raw: Boolean) = Value(stringResource(label), value?.encodeToByteArray(), raw)
@Composable
private fun Value(label: String, bytes: ByteArray?, raw: Boolean, modifier: Modifier = Modifier) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.labelLarge)
        Text(bytes?.let(ByteText::quoted) ?: stringResource(R.string.not_available),
            style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace, textDirection = TextDirection.ContentOrLtr))
        if (raw && bytes != null) {
            Text(stringResource(R.string.exact_bytes_label), style = MaterialTheme.typography.labelSmall)
            Text(ByteText.hex(bytes).ifEmpty { stringResource(R.string.zero_bytes) },
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, textDirection = TextDirection.Ltr))
        }
    }
}
@Composable
private fun Numeric(label: Int, value: String?) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(label), style = MaterialTheme.typography.labelLarge)
        Text(value ?: stringResource(R.string.not_available), style = MaterialTheme.typography.bodyMedium)
    }
}
@Composable
private fun Identity(label: Int, identity: CapturedFileIdentity?) {
    Numeric(label, identity?.let { stringResource(R.string.identity_value, it.device.toString(), it.inode.toString()) })
}

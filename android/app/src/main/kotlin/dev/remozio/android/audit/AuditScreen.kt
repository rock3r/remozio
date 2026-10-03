package dev.remozio.android.audit

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import dev.remozio.android.R
import dev.remozio.android.RemozioApplication
import dev.remozio.phone.audit.*
import dev.remozio.protocol.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.withContext

private class AuditSelection(val scope: CachedAuditScope, val loaded: CachedAuditContent.Loaded, val event: AuditEventMetadata)

@Composable
internal fun AuditScreen() {
    val reader = (LocalContext.current.applicationContext as RemozioApplication).audits
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var mac by remember { mutableStateOf<CborValue.Bytes?>(null) }
    var macLabel by remember { mutableStateOf<String?>(null) }
    var category by remember { mutableStateOf<AuditCategory?>(null) }
    var outcome by remember { mutableStateOf<AuditOutcome?>(null) }
    var retry by remember { mutableIntStateOf(0) }
    var options by remember { mutableStateOf(emptyList<AuditMacOption>()) }
    var selection by remember { mutableStateOf<AuditSelection?>(null) }
    val state by produceState<StoredAuditState>(StoredAuditState.Loading, reader, lifecycle, mac, category, outcome, retry) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            value = StoredAuditState.Loading
            try {
                val result = reader.read(mac, category, outcome)
                if (result is StoredAuditState.Ready) options = result.macs
                value = result
                awaitCancellation()
            } finally { value = StoredAuditState.Loading; selection = null }
        }
    }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        item {
            Text(stringResource(R.string.audit_title), style = MaterialTheme.typography.headlineLarge,
                modifier = Modifier.semantics { heading() })
        }
        item { Text(stringResource(R.string.audit_cached_notice)) }
        item { Text(stringResource(R.string.audit_order_notice), style = MaterialTheme.typography.bodyMedium) }
        item {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                AuditFilter(stringResource(R.string.audit_filter_mac), macLabel ?: stringResource(R.string.audit_all_macs),
                    listOf<CborValue.Bytes?>(null).map { it to stringResource(R.string.audit_all_macs) } + options.map { it.macID to stringResource(R.string.audit_mac_choice, it.label, checkNotNull(auditID(it.macID.copyBytes()))) }) {
                    mac = it; macLabel = options.firstOrNull { option -> option.macID == it }?.label
                }
                AuditFilter(stringResource(R.string.audit_filter_category), category?.let { stringResource(auditLabel(it)) } ?: stringResource(R.string.audit_all_categories),
                    listOf<AuditCategory?>(null).map { it to stringResource(R.string.audit_all_categories) } + AuditCategory.entries.map { it to stringResource(auditLabel(it)) }) { category = it }
                AuditFilter(stringResource(R.string.audit_filter_outcome), outcome?.let { stringResource(auditLabel(it)) } ?: stringResource(R.string.audit_all_outcomes),
                    listOf<AuditOutcome?>(null).map { it to stringResource(R.string.audit_all_outcomes) } + AuditOutcome.entries.map { it to stringResource(auditLabel(it)) }) { outcome = it }
            }
        }
        when (val current = state) {
            StoredAuditState.Loading -> item { Column(verticalArrangement = Arrangement.spacedBy(8.dp)) { CircularProgressIndicator(); Text(stringResource(R.string.audit_loading)) } }
            StoredAuditState.Unavailable -> item {
                AuditNotice(R.string.audit_unavailable_description)
                TextButton(onClick = { retry++ }) { Text(stringResource(R.string.audit_retry)) }
            }
            is StoredAuditState.Ready -> {
                if (current.macs.isEmpty()) item { Text(stringResource(R.string.audit_no_macs)) }
                else if (mac != null && current.macs.none { it.macID == mac }) item { Text(stringResource(R.string.audit_selected_mac_missing)) }
                current.scopes.forEach { scope ->
                    item {
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(scope.label, style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
                            AuditField(R.string.audit_mac_id, auditID(scope.scope.macID.copyBytes()))
                            AuditField(R.string.audit_account_id, auditID(scope.scope.accountID.copyBytes()))
                        }
                    }
                    when (val content = scope.content) {
                        CachedAuditContent.Missing -> item { Text(stringResource(R.string.audit_missing)) }
                        CachedAuditContent.Unavailable -> item { AuditNotice(R.string.audit_scope_unavailable) }
                        is CachedAuditContent.Loaded -> auditGroup(content.history) { selection = AuditSelection(scope, content, it) }
                    }
                }
                item { TextButton(onClick = { retry++ }) { Text(stringResource(R.string.audit_retry)) } }
            }
        }
    }
    selection?.let { selected -> AuditDetails(selected) { selection = null } }
}

@Composable
private fun <T> AuditFilter(title: String, selected: String, choices: List<Pair<T, String>>, onSelect: (T) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        OutlinedButton(onClick = { expanded = true }) { Text("$title: $selected") }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            choices.forEach { (value, label) -> DropdownMenuItem(text = { Text(label) }, onClick = { expanded = false; onSelect(value) }) }
        }
    }
}

private fun LazyListScope.auditGroup(group: AuditHistoryGroup, onEvent: (AuditEventMetadata) -> Unit) {
    if (group.conflictingProofCount > 0) item { AuditNotice(R.string.audit_conflict) }
    if (group.reports.any { it.status.disposition == AuditHistoryDisposition.UNAVAILABLE || it.status.disposition == AuditHistoryDisposition.CURSOR_AHEAD }) {
        item { AuditNotice(R.string.audit_report_discontinuity) }
    }
    if (group.chains.isEmpty()) item { Text(stringResource(R.string.audit_no_segments)) }
    group.chains.forEach { chain ->
        if (group.chains.size > 1) item { AuditNotice(R.string.audit_independent_chain) }
        chain.epochs.forEach { epoch ->
            item {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    HorizontalDivider()
                    Text(stringResource(R.string.audit_segment), style = MaterialTheme.typography.titleMedium)
                    AuditField(R.string.audit_epoch_id, auditID(epoch.epoch.copyBytes()))
                    if (epoch.descriptor == null) Text(stringResource(R.string.audit_segment_unknown))
                    else if (epoch.descriptor?.cause != AuditEpochCause.INITIAL) Text(stringResource(R.string.audit_recovery_segment))
                }
            }
            if (epoch.records.isEmpty()) item { Text(stringResource(if (epoch.retainedRecordCount > 0) R.string.audit_no_matching else R.string.audit_no_events)) }
            items(auditRows(epoch.records, epoch.gaps, newestFirst = true)) { row ->
                when (row) {
                    is AuditRow.Gap -> AuditGapNotice(row.value)
                    is AuditRow.Event -> {
                        val event = row.value
                        Card(onClick = { onEvent(event) }, modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(stringResource(auditLabel(event.kind)), style = MaterialTheme.typography.titleMedium)
                                Text(stringResource(auditLabel(event.category)))
                                AuditField(R.string.audit_outcome, stringResource(auditLabel(event.outcome)))
                                AuditField(R.string.audit_sequence, event.sequence.toString())
                                AuditField(R.string.audit_event_time, auditTime(event.eventTimeMs))
                                Text(stringResource(R.string.audit_event_details), style = MaterialTheme.typography.labelLarge)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AuditGapNotice(gap: AuditHistoryGap) {
    Column {
        Text(stringResource(R.string.audit_gap, gap.after.toString(), gap.through.toString()))
        if (gap.belowRetentionBoundary) Text(stringResource(R.string.audit_retention_gap))
    }
}

@Composable
private fun AuditNotice(resource: Int) {
    Text(stringResource(resource), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
}

@Composable
private fun AuditField(label: Int, value: String?) {
    Column {
        Text(stringResource(label), style = MaterialTheme.typography.labelMedium)
        Text(value ?: stringResource(R.string.audit_not_available), style = MaterialTheme.typography.bodyMedium)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AuditDetails(selection: AuditSelection, onDismiss: () -> Unit) {
    val width = with(LocalDensity.current) { LocalWindowInfo.current.containerSize.width.toDp() }
    val timeline by produceState<AuditHistoryGroup?>(null, selection) {
        selection.event.requestID?.let { request -> value = withContext(Dispatchers.Default) { AuditHistory.timeline(selection.loaded.snapshot, request) } }
    }
    val content: @Composable () -> Unit = {
        Column(Modifier.fillMaxWidth().heightIn(max = 720.dp).padding(24.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(stringResource(R.string.audit_details), style = MaterialTheme.typography.headlineSmall,
                    modifier = Modifier.weight(1f).semantics { heading() })
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.audit_close)) }
            }
            LazyColumn(Modifier.weight(1f, fill = false), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                item { Text(selection.scope.label, style = MaterialTheme.typography.titleMedium) }
                item { Text(stringResource(R.string.audit_not_retained)) }
                item { Text(stringResource(R.string.audit_time_notice)) }
                item { AuditEventDetails(selection.event) }
                timeline?.let { group ->
                    item {
                        Text(stringResource(R.string.audit_timeline), style = MaterialTheme.typography.titleLarge,
                            modifier = Modifier.semantics { heading() })
                        Text(stringResource(R.string.audit_timeline_order))
                    }
                    if (group.conflictingProofCount > 0) item { AuditNotice(R.string.audit_conflict) }
                    group.chains.forEach { chain ->
                        if (group.chains.size > 1) item { AuditNotice(R.string.audit_independent_chain) }
                        chain.epochs.forEach { epoch ->
                            item {
                                HorizontalDivider()
                                AuditField(R.string.audit_epoch_id, auditID(epoch.epoch.copyBytes()))
                            }
                            items(auditRows(epoch.records, epoch.gaps, newestFirst = false)) { row ->
                                when (row) {
                                    is AuditRow.Gap -> AuditGapNotice(row.value)
                                    is AuditRow.Event -> AuditEventDetails(row.value)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if (width < 600.dp) {
        ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberBottomSheetState(
            initialValue = SheetValue.Hidden, enabledValues = setOf(SheetValue.Hidden, SheetValue.Expanded),
        )) { content() }
    } else {
        Dialog(onDismissRequest = onDismiss) {
            Surface(modifier = Modifier.widthIn(max = 720.dp), shape = MaterialTheme.shapes.extraLarge) { content() }
        }
    }
}

@Composable
private fun AuditEventDetails(event: AuditEventMetadata) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(auditLabel(event.kind)), style = MaterialTheme.typography.titleMedium)
        AuditField(R.string.audit_outcome, stringResource(auditLabel(event.outcome)))
        AuditField(R.string.audit_reason, stringResource(auditLabel(event.reason)))
        AuditField(R.string.audit_category, stringResource(auditLabel(event.category)))
        AuditField(R.string.audit_action, event.action?.let { stringResource(auditLabel(it.kind)) })
        AuditField(R.string.audit_lifetime, event.action?.let { stringResource(auditLabel(it.lifetime)) })
        AuditField(R.string.audit_target_scope, event.action?.target?.let { stringResource(auditLabel(it)) })
        AuditField(R.string.audit_authentication, stringResource(auditLabel(event.authentication)))
        AuditField(R.string.audit_event_time, auditTime(event.eventTimeMs))
        AuditField(R.string.audit_receipt_time, auditTime(event.authorityReceiptTimeMs))
        AuditField(R.string.audit_mac_id, auditID(event.macID))
        AuditField(R.string.audit_account_id, auditID(event.accountID))
        AuditField(R.string.audit_request_id, auditID(event.requestID))
        AuditField(R.string.audit_event_id, auditID(event.eventID))
        AuditField(R.string.audit_epoch_id, auditID(event.journalEpoch))
        AuditField(R.string.audit_sequence, event.sequence.toString())
        AuditField(R.string.audit_deciding_phone, auditID(event.decisionPhoneID))
        AuditField(R.string.audit_peer, auditID(event.peerDeviceID))
        AuditField(R.string.audit_dropped_events, event.droppedEventCount?.toString())
    }
}

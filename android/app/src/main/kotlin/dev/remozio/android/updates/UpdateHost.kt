package dev.remozio.android.updates

import java.io.InputStream
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal enum class UpdateHostError { UNAVAILABLE, VERIFICATION, INSTALLATION, CLEANUP }
internal data class UpdateHostState(
    val busy: Boolean = false,
    val installedVersion: String? = null,
    val readyVersion: String? = null,
    val record: UpdateRecord? = null,
    val permissionRequired: Boolean = false,
    val cleanupRequired: Boolean = false,
    val confirmationAvailable: Boolean = false,
    val error: UpdateHostError? = null,
)

/** Application-scoped owner. The supplied scope outlives activities; all blocking work runs on IO. */
internal class UpdateHost(
    private val scope: CoroutineScope,
    private val openRecords: () -> UpdateRecordStore,
    private val verifierFactory: () -> StagedApkVerifier,
    private val backend: (UpdateRecord) -> UpdateInstallBackend,
    private val installedVersion: () -> String,
    private val canInstall: () -> Boolean,
    private val reconcileBeforeIntent: () -> Boolean,
    private val cleanStaging: () -> Boolean,
    private val hasConfirmation: (UpdateCallbackBinding) -> Boolean,
    private val deviceSdk: Int,
) {
    private val mutex = Mutex()
    private val mutableState = MutableStateFlow(UpdateHostState())
    val state = mutableState.asStateFlow()
    private var records: UpdateRecordStore? = null
    private var verifier: StagedApkVerifier? = null
    private var staged: VerifiedApk? = null
    private var installer: UpdateInstaller? = null
    private var recovered = false
    private var orphanCleanup = false
    private var discardCleanup = false

    fun refresh() = operation(UpdateHostError.UNAVAILABLE) {
        initialize()
        val record = records!!.snapshot()
        if (record != null && (record.phase == UpdatePhase.RESERVED || record.phase == UpdatePhase.BOUND)) {
            check(reconcileBeforeIntent())
            records!!.abandonBeforeIntent(record.nonce)
        }
        publish()
    }

    /** The source opens only after admission. The verifier takes ownership of the resulting stream. */
    fun stage(openSource: suspend () -> InputStream) = operation(UpdateHostError.VERIFICATION) {
        initialize()
        check(staged == null && !cleanupPending())
        check(records!!.snapshot()?.phase?.terminal != false)
        try {
            staged = verifier!!.stage(openSource())
            mutableState.value = mutableState.value.copy(permissionRequired = false)
        } catch (error: Exception) {
            orphanCleanup = !cleanStaging()
            if (!orphanCleanup) verifier = verifierFactory()
            throw error
        }
        publish()
    }

    fun install() = operation(UpdateHostError.INSTALLATION) {
        initialize()
        val apk = checkNotNull(staged)
        check(!cleanupPending() && records!!.snapshot()?.phase?.terminal != false)
        if (!canInstall()) {
            mutableState.value = mutableState.value.copy(permissionRequired = true)
            return@operation
        }
        val record = records!!.reserve(apk.identity.packageName, apk.identity.versionCode)
        var retained = true
        mutableState.value = mutableState.value.copy(permissionRequired = false)
        try {
            val coordinator = UpdateInstaller(backend(record), deviceSdk) { records!!.recordCommitIntent(record.nonce, it) }
            installer = coordinator
            retained = false
            val result = coordinator.submit(apk)
            records!!.submitted(record.nonce, result)
        } catch (_: InstallPermissionRequired) {
            retained = true
            mutableState.value = mutableState.value.copy(permissionRequired = true)
        } finally {
            if (!retained) staged = null
            val current = records!!.snapshot()
            if (current != null && (current.phase == UpdatePhase.RESERVED || current.phase == UpdatePhase.BOUND)) {
                if (reconcileBeforeIntent()) records!!.abandonBeforeIntent(current.nonce)
            }
            publish()
        }
    }

    fun discard() = operation(UpdateHostError.CLEANUP) {
        try { staged?.close() } catch (error: Exception) {
            discardCleanup = true
            throw error
        }
        staged = null
        discardCleanup = false
        mutableState.value = mutableState.value.copy(permissionRequired = false)
        publish()
    }

    fun retryCleanup() = operation(UpdateHostError.CLEANUP) {
        if (discardCleanup) {
            staged?.close()
            staged = null
            discardCleanup = false
            mutableState.value = mutableState.value.copy(permissionRequired = false)
        }
        if (installer?.retryCleanup() == false) error("Cleanup is still pending")
        if (orphanCleanup) {
            check(staged == null && cleanStaging())
            orphanCleanup = false
            verifier = verifierFactory()
        }
        initialize()
        publish()
    }

    private fun initialize() {
        if (records == null) records = openRecords()
        if (!recovered) {
            val record = records!!.snapshot()
            if (record == null || record.phase.terminal || record.phase == UpdatePhase.RESERVED || record.phase == UpdatePhase.BOUND) {
                check(reconcileBeforeIntent()) { "Native sessions still need reconciliation" }
                if (record != null && !record.phase.terminal) records!!.abandonBeforeIntent(record.nonce)
            }
            orphanCleanup = !cleanStaging()
            verifier = verifierFactory()
            recovered = true
        }
    }

    private fun cleanupPending() = orphanCleanup || discardCleanup || installer?.cleanupRequired?.value == true

    private fun publish() {
        val record = records?.snapshot()
        val binding = record?.sessionId?.let { UpdateCallbackBinding(it, record.nonce) }
        mutableState.value = mutableState.value.copy(
            installedVersion = installedVersion(),
            readyVersion = staged?.identity?.let { it.versionName ?: it.versionCode.toString() },
            record = record,
            cleanupRequired = cleanupPending(),
            confirmationAvailable = record?.phase == UpdatePhase.AWAITING_USER && binding != null && hasConfirmation(binding),
        )
    }

    private fun operation(error: UpdateHostError, block: suspend () -> Unit) = scope.launch(Dispatchers.IO) {
        mutex.withLock {
            mutableState.value = mutableState.value.copy(busy = true, error = null)
            try { block() }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) {
                runCatching { publish() }
                mutableState.value = mutableState.value.copy(error = error)
            } finally { mutableState.value = mutableState.value.copy(busy = false) }
        }
    }
}

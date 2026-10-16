package dev.remozio.android.push

import android.content.Context
import android.content.Intent
import androidx.work.*
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import dev.remozio.android.RemozioApplication
import dev.remozio.protocol.PushData
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Reject provider notification fields before the pinned SDK can render them outside our callback. */
internal fun acceptsFCMExtras(keys: Set<String>): Boolean = keys.none {
    it.startsWith("gcm.n.") || it.startsWith("gcm.notification.")
}

class RemozioMessagingService : FirebaseMessagingService() {
    override fun handleIntent(intent: Intent) {
        if (intent.action in setOf("com.google.android.c2dm.intent.RECEIVE", "com.google.firebase.messaging.RECEIVE_DIRECT_BOOT")) {
            if ((application as RemozioApplication).pushClient.generation() == null ||
                !acceptsFCMExtras(intent.extras?.keySet().orEmpty())) return
        }
        super.handleIntent(intent)
    }
    @Suppress("OVERRIDE_DEPRECATION")
    override fun onNewToken(token: String) { (application as RemozioApplication).pushClient.tokenChanged() }
    override fun onMessageReceived(message: RemoteMessage) {
        val app = application as RemozioApplication
        val generation = app.pushClient.generation() ?: return
        if (message.notification != null || !app.pushClient.acceptsSender(message.from)) return
        val wake = try { PushData.decode(message.data) as? PushData.Wake } catch (_: Exception) { null } ?: return
        try {
            val manager = WorkManager.getInstance(this)
            val queued = manager.getWorkInfosByTag(WORK_TAG).get(1, TimeUnit.SECONDS)
                .count { !it.state.isFinished }
            if (queued >= MAXIMUM_QUEUED) {
                report(app, generation, PushDeliveryStatus.CAPACITY_LIMIT); return
            }
            val data = workDataOf(GENERATION to generation.toString(), IDENTIFIER to wake.encode()["wake_v1"],
                ENROLLMENT to wake.encode()["enrollment_v1"])
            val request = OneTimeWorkRequestBuilder<FCMWakeWorker>().setInputData(data).addTag(WORK_TAG)
                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST).build()
            val tag = MessageDigest.getInstance("SHA-256").digest(wake.enrollmentTag).joinToString("") { "%02x".format(it.toInt() and 255) }
            report(app, generation, PushDeliveryStatus.QUEUED)
            val operation = manager.enqueueUniqueWork("remozio.fcm." + generation + "." + tag, ExistingWorkPolicy.KEEP, request)
            operation.result.addListener({
                try { operation.result.get() } catch (_: Exception) { report(app, generation, PushDeliveryStatus.UNAVAILABLE) }
            }, { it.run() })
        } catch (_: Exception) { report(app, generation, PushDeliveryStatus.UNAVAILABLE) }
    }
    private companion object {
        const val WORK_TAG = "remozio.fcm.ingress.v1"
        const val MAXIMUM_QUEUED = 256
    }
}

/** Local archive and generic notification work only. It never opens a network connection or signs a decision. */
class FCMWakeWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val generation = try { UUID.fromString(inputData.getString(GENERATION)) } catch (_: Exception) { return Result.failure() }
        val identifier = inputData.getString(IDENTIFIER) ?: return Result.failure()
        val enrollment = inputData.getString(ENROLLMENT) ?: return Result.failure()
        val app = applicationContext as RemozioApplication
        val receipt = app.wakeNotifications.receive(generation, mapOf("wake_v1" to identifier, "enrollment_v1" to enrollment))
        val status = when (receipt?.notification) {
            dev.remozio.phone.push.WakeNotificationResult.POSTED -> PushDeliveryStatus.ALERT_REQUESTED
            dev.remozio.phone.push.WakeNotificationResult.PERMISSION_DENIED,
            dev.remozio.phone.push.WakeNotificationResult.APP_DISABLED -> PushDeliveryStatus.PERMISSION_BLOCKED
            dev.remozio.phone.push.WakeNotificationResult.CHANNEL_DISABLED -> PushDeliveryStatus.CHANNEL_BLOCKED
            dev.remozio.phone.push.WakeNotificationResult.FAILED -> PushDeliveryStatus.UNAVAILABLE
            null -> if (receipt == null) PushDeliveryStatus.UNAVAILABLE else null
        }
        if (status != null) report(app, generation, status)
        return Result.success()
    }
}

private const val GENERATION = "provider_generation"
private const val IDENTIFIER = "wake"
private const val ENROLLMENT = "enrollment"

private fun report(app: RemozioApplication, generation: UUID, status: PushDeliveryStatus) {
    try { app.pushClient.withCurrent(generation) { app.pushDelivery.record(generation, status) } } catch (_: Exception) { }
}

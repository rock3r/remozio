package dev.remozio.android.push

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import dev.remozio.android.MainActivity
import dev.remozio.android.R
import dev.remozio.phone.push.PushWakeRouter
import dev.remozio.phone.push.WakeEnrollment
import dev.remozio.phone.push.WakeNotificationResult
import dev.remozio.phone.push.WakeReceipt
import dev.remozio.phone.requests.ElapsedInstant

/** Generic hints only. Request details and usable actions require a separately authenticated fetch. */
class AndroidWakeNotifications(context: Context, private val timeoutMillis: Long) {
    private val context = context.applicationContext
    private val manager = requireNotNull(this.context.getSystemService(NotificationManager::class.java))

    init { require(timeoutMillis in 1..86_400_000) }

    fun post(enrollment: WakeEnrollment, alert: Boolean): WakeNotificationResult {
        if (context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return WakeNotificationResult.PERMISSION_DENIED
        }
        if (!manager.areNotificationsEnabled()) return WakeNotificationResult.APP_DISABLED
        return try {
            manager.createNotificationChannel(NotificationChannel(CHANNEL_ID,
                context.getString(R.string.request_notification_channel), NotificationManager.IMPORTANCE_HIGH).apply {
                description = context.getString(R.string.request_notification_channel_description)
            })
            if (manager.getNotificationChannel(CHANNEL_ID)?.importance == NotificationManager.IMPORTANCE_NONE) {
                return WakeNotificationResult.CHANNEL_DISABLED
            }
            // The intent opens the app only. No endpoint, request, decision, or approval action comes from a push.
            val intent = Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
            val open = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_launcher_monochrome)
                .setContentTitle(context.getString(R.string.app_name))
                .setContentText(context.getString(R.string.request_notification_generic))
                .setContentIntent(open)
                .setCategory(NotificationCompat.CATEGORY_STATUS)
                .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
                .setAutoCancel(true)
                .setOnlyAlertOnce(!alert)
                .setSilent(!alert)
                .setTimeoutAfter(timeoutMillis)
                .build()
            manager.notify(tag(enrollment), NOTIFICATION_ID, notification)
            WakeNotificationResult.POSTED
        } catch (_: SecurityException) {
            WakeNotificationResult.PERMISSION_DENIED
        } catch (_: RuntimeException) {
            WakeNotificationResult.FAILED
        }
    }

    fun cancel(enrollment: WakeEnrollment) { manager.cancel(tag(enrollment), NOTIFICATION_ID) }

    private fun tag(enrollment: WakeEnrollment): String = "remozio.wake." +
        enrollment.notificationTag.copyBytes().joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private companion object {
        const val CHANNEL_ID = "pending_requests_v1"
        const val NOTIFICATION_ID = 1
    }
}

/** Own alongside the process-local router. The provider listener must schedule bounded fetch work after receive returns. */
class AndroidPushWakeReceiver(
    private val router: PushWakeRouter,
    private val notifications: AndroidWakeNotifications,
    private val clockEpoch: Long,
) {
    fun receive(data: Map<String, String>): WakeReceipt = router.receive(data,
        ElapsedInstant(clockEpoch, SystemClock.elapsedRealtime().toULong()), notifications::post)

    fun remove(enrollment: WakeEnrollment): Boolean {
        if (!router.remove(enrollment)) return false
        notifications.cancel(enrollment)
        return true
    }
}

package dev.alsatianconsulting.pocketpcap.service

import android.app.*
import android.content.Intent
import android.util.Log
import android.os.Binder
import android.os.IBinder
import androidx.core.app.NotificationCompat
import dev.alsatianconsulting.pocketpcap.MainActivity
import dev.alsatianconsulting.pocketpcap.R
import dev.alsatianconsulting.pocketpcap.capture.CaptureManager
import dev.alsatianconsulting.pocketpcap.decode.DecodeManager
import dev.alsatianconsulting.pocketpcap.model.CaptureState

class CaptureService : Service() {

    inner class LocalBinder : Binder() {
        val service get() = this@CaptureService
    }

    val decodeManager by lazy { DecodeManager(this) }
    val captureManager by lazy { CaptureManager(this, decodeManager) }


    private val binder = LocalBinder()

    companion object {
        private const val TAG = "CaptureService"
        const val NOTIFICATION_ID = 1001
        const val CHANNEL_ID = "pocketpcap_capture"
        const val ACTION_STOP = "dev.alsatianconsulting.pocketpcap.ACTION_STOP"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            captureManager.stop()
            stopSelf()
            return START_NOT_STICKY
        }
        // A null intent means the system restarted us under START_STICKY, which
        // happens after a process death with the app in the background. There is no
        // capture left to resume, and Android refuses startForeground() to a
        // background app, so calling it here threw
        // ForegroundServiceStartNotAllowedException and killed the process again.
        if (intent == null) {
            stopSelf()
            return START_NOT_STICKY
        }
        return try {
            startForeground(NOTIFICATION_ID, buildNotification())
            START_STICKY
        } catch (e: Exception) {
            Log.w(TAG, "Could not enter the foreground; stopping", e)
            stopSelf()
            START_NOT_STICKY
        }
    }

    override fun onBind(intent: Intent): IBinder = binder

    override fun onDestroy() {
        captureManager.onDestroy()
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Keep active foreground captures running when the UI task is swiped away;
        // otherwise exit cleanly instead of leaving an idle foreground service.
        val active = captureManager.session.value?.state in setOf(
            CaptureState.STARTING,
            CaptureState.RUNNING,
            CaptureState.PAUSED,
            CaptureState.STOPPING,
        )
        if (!active) stopSelf()
        super.onTaskRemoved(rootIntent)
    }

    fun updateNotification(iface: String, packets: Long) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(iface, packets))
    }

    private fun buildNotification(iface: String = "", packets: Long = 0L): Notification {
        val returnIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pi = PendingIntent.getActivity(this, 0, returnIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

        val stopIntent = Intent(this, CaptureService::class.java).apply { action = ACTION_STOP }
        val stopPi = PendingIntent.getService(this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

        val text = if (iface.isNotEmpty()) "Capturing $iface — $packets packets" else "Ready to capture"

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("PocketPCAP")
            .setContentText(text)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pi)
            .setOngoing(true)
            .addAction(android.R.drawable.ic_media_pause, "Stop", stopPi)
            .build()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Packet Capture",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Active packet capture"
            setShowBadge(false)
        }
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
            .createNotificationChannel(channel)
    }
}

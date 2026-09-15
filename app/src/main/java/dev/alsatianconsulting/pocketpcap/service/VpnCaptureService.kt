package dev.alsatianconsulting.pocketpcap.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import dev.alsatianconsulting.pocketpcap.MainActivity
import dev.alsatianconsulting.pocketpcap.R
import dev.alsatianconsulting.pocketpcap.capture.DirectSocksProxy
import dev.alsatianconsulting.pocketpcap.capture.RootlessCaptureStore
import dev.alsatianconsulting.pocketpcap.capture.RootlessPacketRecorder
import dev.alsatianconsulting.pocketpcap.decode.Prefs
import dev.alsatianconsulting.pocketpcap.model.CaptureSession
import dev.alsatianconsulting.pocketpcap.model.CaptureState
import dev.alsatianconsulting.pocketpcap.storage.SharedCaptureStore
import engine.Engine
import engine.Key
import go.Seq
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Rootless local capture backend. Android routes selected app traffic into this
 * VpnService TUN interface; tun2socks forwards it through a local direct SOCKS relay,
 * and PocketPCAP records forwarded payload packets into pcapng.
 */
class VpnCaptureService : VpnService() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var vpnFd: ParcelFileDescriptor? = null
    private var captureJob: Job? = null
    private var socksProxy: DirectSocksProxy? = null
    private var recorder: RootlessPacketRecorder? = null
    private val stopping = AtomicBoolean(false)
    // tun2socks is a process-wide singleton that closes its device fd inside
    // Engine.stop(). stopCapture() runs on several paths — startCapture() calls it
    // first, and so do onDestroy, onRevoke and the STOP action — so an unconditional
    // Engine.stop() closed that descriptor again and again. Once freed, the number
    // gets reused elsewhere in the process and the next stop trips fdsan, aborting
    // the app. Stop the engine only when one is actually running.
    private val engineRunning = AtomicBoolean(false)

    companion object {
        private const val TAG = "VpnCaptureService"
        const val ACTION_START = "dev.alsatianconsulting.pocketpcap.vpn.START"
        const val ACTION_STOP = "dev.alsatianconsulting.pocketpcap.vpn.STOP"
        const val ACTION_PAUSE = "dev.alsatianconsulting.pocketpcap.vpn.PAUSE"
        const val ACTION_RESUME = "dev.alsatianconsulting.pocketpcap.vpn.RESUME"



        const val EXTRA_FILTER = "filter"
        const val CHANNEL_ID = "pocketpcap_rootless_vpn"
        const val NOTIFICATION_ID = 1002
    }

    override fun onCreate() {
        super.onCreate()
        Seq.setContext(applicationContext)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopCapture()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_PAUSE -> {
                pauseCapture()
                return START_STICKY
            }
            ACTION_RESUME -> {
                resumeCapture()
                return START_STICKY
            }
            ACTION_START -> {
                startForeground(NOTIFICATION_ID, buildNotification("Starting rootless capture"))
                startCapture(filter = intent.getStringExtra(EXTRA_FILTER).orEmpty())
            }
            else -> startForeground(NOTIFICATION_ID, buildNotification("Rootless capture ready"))
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopCapture()
        scope.cancel()
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Keep active foreground VPN captures running when the UI task is swiped away;
        // otherwise exit cleanly instead of leaving an idle foreground service.
        val active = RootlessCaptureStore.session.value?.state in setOf(
            CaptureState.STARTING,
            CaptureState.RUNNING,
            CaptureState.PAUSED,
            CaptureState.STOPPING,
        )
        if (!active) stopSelf()
        super.onTaskRemoved(rootIntent)
    }

    private fun startCapture(filter: String) {
        stopCapture()
        val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val tag = "all"
        // The default output directory is the shared Documents/pocketpcap folder, which
        // an app may not simply write into: the file has to be registered with
        // MediaStore before ordinary writes work on it. A capture still has to go
        // somewhere if that fails, so fall back to app-private storage.
        val prefs = Prefs(this)
        val name = "capture_vpn_${tag}_$ts.pcapng"
        val outFile = SharedCaptureStore.newFile(this, File(prefs.outputDir), name)
            ?: File(File(prefs.fallbackCaptureDir).apply { mkdirs() }, name)
        val session = CaptureSession(
            id = UUID.randomUUID().toString(),
            interfaceName = "Rootless VPN (all apps)",
            startTime = System.currentTimeMillis(),
            outputPath = outFile.absolutePath,
            filter = filter,
            state = CaptureState.STARTING,
        )
        RootlessCaptureStore.clearPackets()
        RootlessCaptureStore.setSession(session)

        val builder = Builder()
            .setSession("PocketPCAP rootless capture")
            .setMtu(1500)
            .addAddress("10.215.0.2", 32)
            .addRoute("0.0.0.0", 0)

        runCatching {
            builder
                .addAddress("fd00:215::2", 128)
                .addRoute("::", 0)
        }

        // PocketPCAP must never be routed into its own tunnel: the local SOCKS relay
        // would forward its own forwarded traffic straight back through the TUN.
        // Excluding our own package needs no package-visibility permission.
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.e(TAG, "Could not exclude PocketPCAP from its own tunnel", e)
            RootlessCaptureStore.setSession(session.copy(state = CaptureState.ERROR))
            return
        }

        vpnFd = try {
            builder.establish()
        } catch (_: Exception) {
            null
        }
        val fd = vpnFd
        if (fd == null) {
            RootlessCaptureStore.setSession(session.copy(state = CaptureState.ERROR))
            return
        }

        val activeRecorder = RootlessPacketRecorder(session, outFile, filter)
        val proxy = DirectSocksProxy(this, scope, activeRecorder)
        recorder = activeRecorder
        socksProxy = proxy
        val socksPort = proxy.start()
        Log.i(TAG, "Starting rootless tun2socks capture on SOCKS port $socksPort")
        engineRunning.set(true)
        captureJob = scope.launch { runTun2Socks(fd, socksPort) }
    }

    private suspend fun runTun2Socks(fd: ParcelFileDescriptor, socksPort: Int) {
        // Detached, so nothing else will close it: if the engine never takes
        // ownership we have to, or every failed start leaks a descriptor.
        var engineFd = -1
        RootlessCaptureStore.setSession(RootlessCaptureStore.session.value?.copy(state = CaptureState.RUNNING))
        updateNotification("Forwarding rootless VPN traffic")
        try {
            // tun2socks takes ownership of whatever descriptor it is handed and closes
            // it when the engine stops. Handing it `fd.fd` gave it the same descriptor
            // the VpnService ParcelFileDescriptor owns, so on teardown the fd was closed
            // twice; the number was recycled in between and the next unrelated close in
            // the process tripped fdsan and aborted it (seen landing on RenderThread).
            // Give the engine a detached dup instead: one owner per descriptor, and the
            // VpnService PFD stays ours to close.
            engineFd = ParcelFileDescriptor.dup(fd.fileDescriptor).detachFd()
            val key = Key().apply {
                setDevice("fd://$engineFd")
                setProxy("socks5://127.0.0.1:$socksPort")
                setMTU(1500)
                setLogLevel("error")
                setInterface("")
                setTCPModerateReceiveBuffer(true)
            }
            Engine.insert(key)
            Engine.start()
            Log.i(TAG, "tun2socks Engine.start returned; keeping rootless VPN service active")
            while (currentCoroutineContext().isActive) delay(1_000)
        } catch (e: Exception) {
            Log.e(TAG, "Rootless tun2socks capture failed", e)
            // The engine never got as far as owning the dup, so close it here.
            // adoptFd takes the raw descriptor back under a ParcelFileDescriptor
            // purely so close() can release it.
            if (engineFd >= 0) runCatching {
                ParcelFileDescriptor.adoptFd(engineFd).close()
            }
            RootlessCaptureStore.setSession(RootlessCaptureStore.session.value?.copy(state = CaptureState.ERROR))
        } finally {
            finishCaptureStopped()
        }
    }


    private fun pauseCapture() {
        val recording = recorder ?: return
        recording.pause()
        RootlessCaptureStore.setSession(
            RootlessCaptureStore.session.value?.copy(state = CaptureState.PAUSED)
        )
        updateNotification("Rootless capture paused — tunnel still up")
    }

    private fun resumeCapture() {
        val recording = recorder ?: return
        recording.resume()
        RootlessCaptureStore.setSession(
            RootlessCaptureStore.session.value?.copy(state = CaptureState.RUNNING)
        )
        updateNotification("Forwarding rootless VPN traffic")
    }

    private fun stopCapture() {
        if (!stopping.compareAndSet(false, true)) return
        try {
            Log.i(TAG, "Stopping rootless VPN capture")
            val current = RootlessCaptureStore.session.value
            if (current != null && current.state in setOf(CaptureState.STARTING, CaptureState.RUNNING, CaptureState.PAUSED)) {
                RootlessCaptureStore.setSession(current.copy(state = CaptureState.STOPPING))
            }
            if (engineRunning.compareAndSet(true, false)) runCatching { Engine.stop() }
            captureJob?.cancel()
            captureJob = null
            finishCaptureStopped()
        } finally {
            stopping.set(false)
        }
    }

    /**
     * Tear the capture down exactly once.
     *
     * Two paths race here: stopCapture() on the main thread, and the capture
     * coroutine's `finally` once that cancel lands on another thread. Unguarded,
     * both observed the same non-null proxy and closed its ServerSocket twice.
     * By the second close that fd number had already been recycled by the TUN's
     * ParcelFileDescriptor, so fdsan saw a close of a descriptor owned by someone
     * else and aborted the process — which killed the recorder before it could
     * flush and left the pcapng cut off mid-packet. Claim each resource under the
     * lock so the losing caller has nothing left to tear down.
     */
    @Synchronized
    private fun finishCaptureStopped() {
        val proxy = socksProxy; socksProxy = null
        val recording = recorder; recorder = null
        val fd = vpnFd; vpnFd = null
        if (proxy == null && recording == null && fd == null) return
        Log.i(TAG, "Cleaning up rootless VPN capture")
        val current = RootlessCaptureStore.session.value
        // Stop inbound traffic first, then flush. Each step is guarded separately so
        // a failure closing the proxy can never skip the writer close and cost us
        // the tail of the capture file.
        runCatching { proxy?.stop() }
        runCatching { recording?.close() }
        runCatching { fd?.close() }
        // The recorder wrote straight to the path, so MediaStore still believes the
        // file is the empty one it created; without this the Files app lists every
        // rootless capture as 0 B.
        current?.outputPath?.let { runCatching { SharedCaptureStore.refresh(this, File(it)) } }
        if (current != null) {
            RootlessCaptureStore.setSession(current.copy(state = CaptureState.STOPPED))
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).cancel(NOTIFICATION_ID)
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        val returnIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pi = PendingIntent.getActivity(
            this, 0, returnIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = Intent(this, VpnCaptureService::class.java).apply { action = ACTION_STOP }
        val stopPi = PendingIntent.getService(
            this, 1, stopIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("PocketPCAP rootless VPN")
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
            "Rootless VPN Capture",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Rootless local packet capture through Android VpnService"
            setShowBadge(false)
        }
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(channel)
    }
}

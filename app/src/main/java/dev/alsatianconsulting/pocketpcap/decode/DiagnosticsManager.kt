package dev.alsatianconsulting.pocketpcap.decode

import android.content.Context
import dev.alsatianconsulting.pocketpcap.storage.SharedCaptureStore
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Non-IP diagnostic sources that are preserved as raw logs and (where possible)
 * decoded through the same tshark pipeline as ordinary captures.
 *
 *  - Bluetooth HCI snoop  → Android writes a `btsnoop_hci.log` when HCI snoop
 *    logging is enabled. tshark reads the btsnoop format natively, so we convert
 *    it to pcapng and it flows through the existing packet list / decode tree /
 *    raw bytes views with full HCI + BLE dissection.
 *  - RIL / modem logs     → the Android `radio` logcat buffer carries RIL request/
 *    response traffic and modem activity. These cannot be represented as pcapng,
 *    so they are preserved verbatim as text logs (MVP requirement #4/#12).
 *
 * Everything runs through `su`; strictly read-only collection of logs the device
 * already produces. No injection, no interception beyond what root legitimately
 * exposes.
 */
class DiagnosticsManager(private val context: Context, private val bundle: TsharkBundle) {

    /** Same app-private captures directory the capture list scans, so btsnoop shows up there. */
    private val capturesDir: File
        get() = SharedCaptureStore.privateDir(context, SharedCaptureStore.CAPTURES).apply { mkdirs() }
    private val logsDir: File
        get() = SharedCaptureStore.privateDir(context, SharedCaptureStore.LOGS).apply { mkdirs() }

    data class Result(val ok: Boolean, val message: String, val path: String? = null)

    companion object {
        // Known btsnoop locations across vendor/Android versions.
        private val BTSNOOP_PATHS = listOf(
            "/data/misc/bluetooth/logs/btsnoop_hci.log",
            "/data/misc/bluedroid/btsnoop_hci.log",
            "/data/log/bt/btsnoop_hci.log",
            "/sdcard/btsnoop_hci.log",
            "/sdcard/Android/data/btsnoop_hci.log",
        )
    }

    // --- Bluetooth HCI --------------------------------------------------------


    private fun findBtsnoopLog(): String? {
        for (p in BTSNOOP_PATHS) {
            val r = RootShell.run("test -s '$p' && echo FOUND", timeoutMs = 6_000)
            if (r.stdout.contains("FOUND")) return p
        }
        return null
    }

    /**
     * Best-effort enable of Android's Bluetooth HCI snoop logging via root, then
     * restart the Bluetooth stack so it takes effect. Some builds only begin
     * writing the snoop log after a reboot, which we surface to the user.
     */
    fun enableBtsnoop(): Result {
        if (!RootShell.hasRoot()) return Result(false, "Root required to enable HCI snoop")
        RootShell.run("settings put global bluetooth_btsnoop_log_mode full", timeoutMs = 8_000)
        // resetprop bypasses SELinux restrictions on persist props (Magisk).
        RootShell.run("resetprop persist.bluetooth.btsnooplogmode full", timeoutMs = 8_000)
        RootShell.run("cmd bluetooth_manager disable", timeoutMs = 8_000)
        RootShell.run("cmd bluetooth_manager enable", timeoutMs = 12_000)
        return Result(
            true,
            "HCI snoop logging enabled. Use Bluetooth to generate activity, then tap " +
                "\"Collect Bluetooth HCI\". If no log appears, reboot once to apply.",
        )
    }

    /**
     * Convert the device's btsnoop HCI log into a pcapng capture file. tshark runs
     * as root (so it can read the protected log) and writes pcapng into the app's
     * captures dir, where it appears in Files and decodes like any other capture.
     */
    fun collectBtsnoop(): Result {
        if (!bundle.ensureExtracted()) return Result(false, "Decode engine not ready")
        val src = findBtsnoopLog() ?: return Result(
            false,
            "No HCI snoop log found. Enable HCI snoop, reproduce Bluetooth activity, then retry.",
        )
        val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val out = File(capturesDir, "bluetooth_hci_$ts.pcapng")
        // Format conversion only reads and rewrites a file, so run tshark directly.
        val argv = bundle.tsharkArgv(listOf("-r", src, "-F", "pcapng", "-w", out.absolutePath))
        // tshark now writes as the app itself, so the output needs no chown back.
        val res = Exec.run(argv, bundle.env(), timeoutMs = 60_000)
        return if (out.exists() && out.length() > 40) {
            Result(true, "Collected Bluetooth HCI snoop → ${out.name}", out.absolutePath)
        } else {
            val err = res.stderr.lineSequence().firstOrNull { it.isNotBlank() }?.take(140) ?: "no packets"
            Result(false, "HCI snoop log present but decode produced nothing: $err")
        }
    }

    // --- RIL / modem logs -----------------------------------------------------

    /**
     * Preserve the radio (RIL/modem) logcat buffer as a raw text log. The app
     * writes the file itself from su stdout to avoid FUSE write issues, and caps
     * the dump so it stays UI-friendly.
     */
    fun collectRilLogs(): Result {
        if (!RootShell.hasRoot()) return Result(false, "Root required for RIL logs")
        val res = RootShell.run("logcat -b radio -d -v time -t 20000", timeoutMs = 30_000)
        val body = res.stdout
        if (body.isBlank()) return Result(false, "Radio log buffer is empty or inaccessible")
        val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val out = File(logsDir, "ril_$ts.log")
        // Note any accessible vendor radio log files (preserved-in-place reference).
        val vendor = RootShell.run(
            "ls -1 /data/vendor/radio/logs/always-on 2>/dev/null; ls -1 /data/vendor/radio/extended_logs 2>/dev/null",
            timeoutMs = 8_000,
        ).stdout.lineSequence().filter { it.isNotBlank() }.toList()
        val header = buildString {
            appendLine("# PocketPCAP RIL / modem log snapshot")
            appendLine("# Captured: ${Date()}")
            appendLine("# Source: logcat -b radio (RIL request/response + modem activity)")
            if (vendor.isNotEmpty()) {
                appendLine("# Vendor radio log files present (root-only, preserved in place):")
                vendor.forEach { appendLine("#   /data/vendor/radio/.../$it") }
            }
            appendLine("# ----------------------------------------------------------------")
        }
        return try {
            out.writeText(header + body)
            val lines = body.lineSequence().count()
            Result(true, "Saved RIL log → ${out.name} ($lines lines)", out.absolutePath)
        } catch (e: Exception) {
            Result(false, "Failed to write RIL log: ${e.message}")
        }
    }

    // --- Diagnostic log listing ----------------------------------------------

    /** List preserved raw diagnostic logs (text) for the Files screen. */
    fun listDiagnosticLogs(): List<File> =
        logsDir.listFiles { f -> f.isFile && f.extension == "log" }
            ?.sortedByDescending { it.lastModified() }
            ?.toList() ?: emptyList()

    fun readLog(path: String, maxChars: Int = 400_000): String = try {
        val f = File(path)
        val text = f.readText()
        if (text.length > maxChars) "…(truncated)…\n" + text.takeLast(maxChars) else text
    } catch (e: Exception) {
        "Unable to read log: ${e.message}"
    }
}

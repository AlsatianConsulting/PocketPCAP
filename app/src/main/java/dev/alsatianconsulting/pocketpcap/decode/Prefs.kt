package dev.alsatianconsulting.pocketpcap.decode

import android.content.Context
import dev.alsatianconsulting.pocketpcap.storage.SharedCaptureStore

/**
 * Lightweight persisted settings backed by SharedPreferences: the capture output
 * directory, packet display preferences and the rooted-capture autostop ceilings.
 */
class Prefs(context: Context) {

    private val sp = context.getSharedPreferences("pocketpcap", Context.MODE_PRIVATE)

    /** Where output goes when the shared folder cannot be used. */
    val fallbackCaptureDir: String =
        SharedCaptureStore.privateDir(context, SharedCaptureStore.CAPTURES).absolutePath

    /**
     * Documents/pocketpcap, so captures land somewhere a person can actually find
     * them - in the Files app, or over USB - instead of under Android/data where
     * only a file manager with special access can reach them.
     *
     * Writing there needs [SharedCaptureStore]; it is not a directory the app may
     * simply mkdir, and on Android 10 it cannot be written by path at all. Where that
     * is the case the default is the app-private captures directory, so Settings shows
     * the path output actually goes to rather than one it silently falls back from.
     */
    private val defaultCaptureDir =
        if (SharedCaptureStore.available) SharedCaptureStore.directory().absolutePath
        else fallbackCaptureDir

    var outputDir: String
        get() = sp.getString(KEY_OUTPUT_DIR, defaultCaptureDir) ?: defaultCaptureDir
        set(value) = sp.edit().putString(KEY_OUTPUT_DIR, value).apply()

    fun resetOutputDir() = sp.edit().remove(KEY_OUTPUT_DIR).apply()

    /** Endpoint display mode: "ADDRESS" | "NAME_ADDRESS" | "NAME". */
    var displayMode: String
        get() = sp.getString(KEY_DISPLAY_MODE, "ADDRESS") ?: "ADDRESS"
        set(value) = sp.edit().putString(KEY_DISPLAY_MODE, value).apply()

    /** Whether reverse-DNS / mDNS name resolution is enabled. */
    var resolveHostnames: Boolean
        get() = sp.getBoolean(KEY_RESOLVE_HOSTNAMES, false)
        set(value) = sp.edit().putBoolean(KEY_RESOLVE_HOSTNAMES, value).apply()

    // ---- capture autostop -------------------------------------------------

    /**
     * Stop a rooted capture once the file reaches this many megabytes, 0 to disable.
     *
     * A capture left running writes until the volume fills, which on a phone takes
     * the whole device down with it, so an explicit ceiling is offered. Enforced by
     * dumpcap itself via tshark's `-a filesize:` autostop, in kilobytes.
     */
    var maxCaptureMb: Int
        get() = sp.getInt(KEY_MAX_CAPTURE_MB, DEFAULT_MAX_CAPTURE_MB)
        set(value) = sp.edit().putInt(KEY_MAX_CAPTURE_MB, value.coerceAtLeast(0)).apply()

    /** Stop a rooted capture after this many minutes, 0 to disable. */
    var maxCaptureMinutes: Int
        get() = sp.getInt(KEY_MAX_CAPTURE_MINUTES, 0)
        set(value) = sp.edit().putInt(KEY_MAX_CAPTURE_MINUTES, value.coerceAtLeast(0)).apply()

    companion object {
        const val DEFAULT_MAX_CAPTURE_MB = 512

        private const val KEY_OUTPUT_DIR = "output_dir"
        private const val KEY_DISPLAY_MODE = "display_mode"
        private const val KEY_RESOLVE_HOSTNAMES = "resolve_hostnames"
        private const val KEY_MAX_CAPTURE_MB = "max_capture_mb"
        private const val KEY_MAX_CAPTURE_MINUTES = "max_capture_minutes"
    }
}

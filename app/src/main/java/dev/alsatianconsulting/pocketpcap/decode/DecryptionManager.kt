package dev.alsatianconsulting.pocketpcap.decode

import android.content.Context
import android.net.Uri
import java.io.File

/**
 * User-supplied decryption material applied during tshark decode.
 *
 * Strictly user-driven (MVP requirement #10): the user imports a TLS key-log
 * file (SSLKEYLOGFILE format) or enters a Wi-Fi WPA passphrase, and those are
 * passed to tshark via -o options when decoding. No forced decryption, no key
 * harvesting. Backed by SharedPreferences so DecodeManager always reads the
 * current material.
 *
 * Note on scope: 802.11 decryption only applies to captures that contain raw
 * 802.11 frames, and for WPA/WPA2 only when the EAPOL four-way handshake for the
 * session is present. PocketPCAP cannot record those itself — it captures at L3 —
 * so this is for captures opened from elsewhere, such as a monitor-mode capture
 * taken with an external adapter. TLS key-log decryption works on any captured IP
 * traffic when the user provides the matching key log.
 */
/** An 802.11 key type, named as Wireshark's `80211_keys` UAT expects it. */
enum class WifiKeyType(val uat: String, val label: String, val hint: String) {
    WPA_PWD("wpa-pwd", "WPA/WPA2 passphrase", "passphrase:SSID"),
    WPA_PSK("wpa-psk", "WPA/WPA2 raw PSK", "64 hex characters"),
    WEP("wep", "WEP key", "10 or 26 hex characters"),
}

data class WifiKey(val type: WifiKeyType, val value: String) {
    /**
     * Never render a passphrase back to the screen in full.
     *
     * The stored form is "passphrase:SSID", and a WPA passphrase may itself contain
     * a colon. Splitting on the *first* one showed the remainder of the passphrase
     * as if it were the SSID - for "co:rrect horse" on "HomeNet" the row read
     * "•••••• : rrect horse:HomeNet". Split on the last colon instead: that can
     * still misread an SSID containing one, but it never discloses the secret.
     */
    val masked: String
        get() = when (type) {
            WifiKeyType.WPA_PWD -> {
                val ssid = value.substringAfterLast(':', "")
                if (ssid.isBlank()) "••••••" else "•••••• : $ssid"
            }
            else -> value.take(4) + "…" + value.takeLast(4)
        }

    companion object {
        /**
         * Reject input tshark would silently ignore, so a mistyped key surfaces here
         * rather than as a capture that mysteriously will not decrypt.
         */
        fun validate(type: WifiKeyType, raw: String): String? {
            val v = raw.trim()
            if (v.isEmpty()) return "Enter a key."
            return when (type) {
                WifiKeyType.WPA_PWD -> {
                    // Same split as `masked`: the passphrase is everything before the
                    // last colon, so one containing a colon is measured in full rather
                    // than being rejected on its first fragment.
                    val pass = if (v.contains(':')) v.substringBeforeLast(':') else v
                    if (pass.length !in 8..63) "A WPA passphrase is 8 to 63 characters." else null
                }
                WifiKeyType.WPA_PSK ->
                    if (!v.matches(Regex("[0-9a-fA-F]{64}"))) "A raw PSK is exactly 64 hex characters." else null
                WifiKeyType.WEP -> {
                    val hex = v.removePrefix("0x")
                    if (!hex.matches(Regex("([0-9a-fA-F]{2})+"))) "A WEP key is hexadecimal."
                    else if (hex.length !in setOf(10, 26, 32)) "A WEP key is 10, 26 or 32 hex characters."
                    else null
                }
            }
        }
    }
}

class DecryptionManager(private val context: Context) {

    private val prefs = context.getSharedPreferences("decryption", Context.MODE_PRIVATE)

    private companion object {
        const val KEY_WIFI_KEYS = "wifi_keys"
        // Unit/record separators: no escaping needed, and neither can occur in a key.
        const val FIELD_SEP = "\u001f"
        const val RECORD_SEP = "\u001e"
    }

    private val keysDir: File get() = File(context.filesDir, "keys").apply { mkdirs() }
    private val keylogFile: File get() = File(keysDir, "tls_keylog.txt")

    var tlsKeylogEnabled: Boolean
        get() = prefs.getBoolean("tls_enabled", false) && keylogFile.exists()
        set(v) { prefs.edit().putBoolean("tls_enabled", v).apply() }

    val tlsKeylogPresent: Boolean get() = keylogFile.exists()
    val tlsKeylogLines: Int
        get() = try { if (keylogFile.exists()) keylogFile.readLines().count { it.isNotBlank() } else 0 }
                catch (_: Exception) { 0 }

    /**
     * 802.11 keys, applied in the order given. Wireshark tries each in turn, so a
     * capture spanning several networks can be decrypted with one key list.
     */
    var wifiKeys: List<WifiKey>
        get() = readKeys()
        set(v) { prefs.edit().putString(KEY_WIFI_KEYS, serialiseKeys(v)).apply() }

    var wifiEnabled: Boolean
        get() = prefs.getBoolean("wifi_enabled", false) && wifiKeys.isNotEmpty()
        set(v) { prefs.edit().putBoolean("wifi_enabled", v).apply() }

    /** Append a key, ignoring one that is already present. Returns the new list. */
    fun addWifiKey(key: WifiKey): List<WifiKey> {
        val updated = (wifiKeys + key).distinct()
        wifiKeys = updated
        if (updated.isNotEmpty()) wifiEnabled = true
        return updated
    }

    fun removeWifiKey(key: WifiKey): List<WifiKey> {
        val updated = wifiKeys - key
        wifiKeys = updated
        return updated
    }

    private fun readKeys(): List<WifiKey> {
        val raw = prefs.getString(KEY_WIFI_KEYS, null)
        if (raw == null) return migrateLegacyKey()
        return raw.split(RECORD_SEP).mapNotNull { entry ->
            val parts = entry.split(FIELD_SEP, limit = 2)
            if (parts.size != 2) return@mapNotNull null
            val type = WifiKeyType.entries.firstOrNull { it.uat == parts[0] } ?: return@mapNotNull null
            parts[1].takeIf { it.isNotBlank() }?.let { WifiKey(type, it) }
        }
    }

    private fun serialiseKeys(keys: List<WifiKey>): String =
        keys.joinToString(RECORD_SEP) { "${it.type.uat}$FIELD_SEP${it.value}" }

    /**
     * Carry a previously saved SSID/passphrase pair into the key list, so upgrading
     * does not silently drop a key the operator had already entered.
     */
    private fun migrateLegacyKey(): List<WifiKey> {
        val ssid = prefs.getString("wifi_ssid", "").orEmpty()
        val pass = prefs.getString("wifi_pass", "").orEmpty()
        if (ssid.isBlank() || pass.isBlank()) return emptyList()
        val migrated = listOf(WifiKey(WifiKeyType.WPA_PWD, "$pass:$ssid"))
        prefs.edit()
            .putString(KEY_WIFI_KEYS, serialiseKeys(migrated))
            .remove("wifi_ssid").remove("wifi_pass")
            .apply()
        return migrated
    }

    /** Copy a user-picked SSLKEYLOGFILE into private storage. Returns line count or -1. */
    fun importKeylog(uri: Uri): Int {
        return try {
            context.contentResolver.openInputStream(uri)?.use { input ->
                keylogFile.outputStream().use { input.copyTo(it) }
            } ?: return -1
            tlsKeylogEnabled = true
            tlsKeylogLines
        } catch (e: Exception) { -1 }
    }

    fun clearKeylog() {
        try { keylogFile.delete() } catch (_: Exception) {}
        tlsKeylogEnabled = false
    }

    /** tshark `-o` arguments for the currently enabled decryption material. */
    fun optionArgs(): List<String> {
        val args = mutableListOf<String>()
        if (tlsKeylogEnabled && keylogFile.exists()) {
            args += "-o"; args += "tls.keylog_file:${keylogFile.absolutePath}"
        }
        val keys = wifiKeys
        if (wifiEnabled && keys.isNotEmpty()) {
            args += "-o"; args += "wlan.enable_decryption:TRUE"
            // One UAT row per key: `uat:80211_keys:"<type>","<value>"`. Repeating the
            // option appends rows, so every key is offered to the dissector. These go
            // through Exec as single argv elements, so the quotes are literal and
            // there is no shell to re-interpret them.
            keys.forEach { key ->
                args += "-o"
                args += "uat:80211_keys:\"${key.type.uat}\",\"${key.value}\""
            }
        }
        return args
    }
}

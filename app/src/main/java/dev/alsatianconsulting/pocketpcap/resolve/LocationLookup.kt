package dev.alsatianconsulting.pocketpcap.resolve

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import android.util.Log
import java.net.HttpURLConnection
import java.net.URL

/**
 * Resolves a public endpoint's geographic location (GeoIP) and registration details
 * (WHOIS, via RDAP). Both sources are free, key-less and HTTPS:
 *   - GeoIP: ipwho.is  (country/region/city/lat-lon, ASN, ISP/org)
 *   - WHOIS: rdap.org  (network name, CIDR, registrant org, abuse contact, RIR)
 *
 * This is an **online, user-initiated** lookup: the endpoint's IP is sent to the
 * services above. Private/link-local addresses are reported as local without any
 * network call. Parsing is split into pure functions for unit testing.
 */
object LocationLookup {

    private const val GEO_URL = "https://ipwho.is/"
    private const val RDAP_URL = "https://rdap.org/ip/"
    private const val UA = "PocketPCAP/0.1 (+https://github.com/AlsatianConsulting)"
    private const val TAG = "LocationLookup"

    /** RDAP adds org/ASN detail; skip it when the offline record already carries that. */
    private fun rdapNeededFor(geo: EndpointLocation): Boolean =
        geo.org.isNullOrBlank() && geo.asn.isNullOrBlank()

    /** Full lookup: merges offline/online GeoIP and RDAP. Safe to call from a background coroutine. */
    /**
     * @param allowOnline whether third-party lookups may be used. When false this never
     *   touches the network: the imported offline database is the only source, so a user
     *   who has not opted in cannot have addresses from their capture disclosed by any
     *   path through here. Gated at this level on purpose - a check in the UI could be
     *   bypassed by a future caller, this cannot.
     */
    suspend fun lookup(
        address: String,
        timeoutMs: Int = 12_000,
        offlineGeo: EndpointLocation? = null,
        allowOnline: Boolean = true,
    ): EndpointLocation =
        withContext(Dispatchers.IO) {
            val addr = address.trim()
            if (AddressUtil.isPrivateIpv4(addr) || isLocalV6(addr)) {
                return@withContext EndpointLocation(addr, isPrivate = true)
            }
            if (!AddressUtil.isIpAddress(addr)) {
                return@withContext EndpointLocation(addr, error = "Not an IP address.")
            }
            var geo: EndpointLocation? = offlineGeo
            var rdap: EndpointLocation? = null
            if (!allowOnline) return@withContext geo ?: EndpointLocation(addr)
            if (geo == null) {
                try { httpGet(GEO_URL + addr, timeoutMs)?.let { geo = parseGeo(addr, it) } }
                catch (e: Exception) { Log.w(TAG, "geo parse failed for $addr", e) }
            }
            // Only worth asking RDAP when geolocation did not already answer: it is a
            // second disclosure of the same address to a second third party, and the
            // offline database exists precisely so the network need not be touched.
            val geoSoFar = geo
            if (geoSoFar == null || rdapNeededFor(geoSoFar)) {
                try { httpGet(RDAP_URL + addr, timeoutMs)?.let { rdap = parseRdap(addr, it) } }
                catch (e: Exception) { Log.w(TAG, "rdap parse failed for $addr", e) }
            }
            merge(addr, geo, rdap)
        }

    /** Merge the GeoIP and RDAP partials into one [EndpointLocation]. */
    fun merge(address: String, geo: EndpointLocation?, rdap: EndpointLocation?): EndpointLocation {
        if (geo == null && rdap == null) {
            return EndpointLocation(address, error = "Lookup failed (offline or rate-limited).")
        }
        return EndpointLocation(
            address = address,
            country = geo?.country,
            countryCode = geo?.countryCode,
            region = geo?.region,
            city = geo?.city,
            postal = geo?.postal,
            latitude = geo?.latitude,
            longitude = geo?.longitude,
            flagEmoji = geo?.flagEmoji,
            timezone = geo?.timezone,
            geoSource = geo?.geoSource,
            asn = geo?.asn,
            org = geo?.org,
            isp = geo?.isp,
            netName = rdap?.netName,
            cidr = rdap?.cidr,
            registrant = rdap?.registrant,
            rdapCountry = rdap?.rdapCountry,
            abuseEmail = rdap?.abuseEmail,
            rir = rdap?.rir,
        )
    }

    // --- Pure parsers ---------------------------------------------------------

    /** Parse an ipwho.is GeoIP JSON response. */
    fun parseGeo(address: String, json: String): EndpointLocation? {
        return try {
            val o = JSONObject(json)
            if (!o.optBoolean("success", true)) {
                return EndpointLocation(address, error = o.optString("message").ifBlank { "GeoIP lookup failed." })
            }
            val conn = o.optJSONObject("connection")
            val flag = o.optJSONObject("flag")
            val tz = o.optJSONObject("timezone")
            val asnNum = conn?.optInt("asn", 0) ?: 0
            EndpointLocation(
                address = address,
                country = o.optStringOrNull("country"),
                countryCode = o.optStringOrNull("country_code"),
                region = o.optStringOrNull("region"),
                city = o.optStringOrNull("city"),
                postal = o.optStringOrNull("postal"),
                latitude = o.optDoubleOrNull("latitude"),
                longitude = o.optDoubleOrNull("longitude"),
                flagEmoji = flag?.optStringOrNull("emoji"),
                timezone = tz?.optStringOrNull("id"),
                geoSource = "ipwho.is",
                asn = if (asnNum > 0) "AS$asnNum" else null,
                org = conn?.optStringOrNull("org"),
                isp = conn?.optStringOrNull("isp"),
            )
        } catch (_: Exception) { null }
    }

    /** Parse an RDAP (rdap.org / RIR) IP-network JSON response. */
    fun parseRdap(address: String, json: String): EndpointLocation? {
        return try {
            val o = JSONObject(json)
            val cidr = o.optJSONArray("cidr0_cidrs")?.optJSONObject(0)?.let { c ->
                val v4 = c.optStringOrNull("v4prefix"); val v6 = c.optStringOrNull("v6prefix")
                val len = c.optInt("length", -1)
                when {
                    v4 != null && len >= 0 -> "$v4/$len"
                    v6 != null && len >= 0 -> "$v6/$len"
                    else -> null
                }
            } ?: run {
                val s = o.optStringOrNull("startAddress"); val e = o.optStringOrNull("endAddress")
                if (s != null && e != null) "$s – $e" else null
            }
            var registrant: String? = null
            var abuse: String? = null
            walkEntities(o.optJSONArray("entities")) { roles, fn, email ->
                if (registrant == null && roles.contains("registrant")) registrant = fn
                if (abuse == null && roles.contains("abuse")) abuse = email ?: abuse
            }
            EndpointLocation(
                address = address,
                netName = o.optStringOrNull("name"),
                cidr = cidr,
                registrant = registrant,
                rdapCountry = o.optStringOrNull("country"),
                abuseEmail = abuse,
                rir = rirFrom(o),
            )
        } catch (_: Exception) { null }
    }

    private fun walkEntities(
        arr: org.json.JSONArray?,
        onEntity: (roles: List<String>, fn: String?, email: String?) -> Unit,
    ) {
        if (arr == null) return
        for (i in 0 until arr.length()) {
            val e = arr.optJSONObject(i) ?: continue
            val roles = e.optJSONArray("roles")?.let { r ->
                (0 until r.length()).mapNotNull { r.optString(it).ifBlank { null } }
            } ?: emptyList()
            var fn: String? = null; var email: String? = null
            val vcard = e.optJSONArray("vcardArray")?.optJSONArray(1)
            if (vcard != null) {
                for (j in 0 until vcard.length()) {
                    val item = vcard.optJSONArray(j) ?: continue
                    when (item.optString(0)) {
                        "fn" -> if (fn == null) fn = item.optString(3).ifBlank { null }
                        "email" -> if (email == null) email = item.optString(3).ifBlank { null }
                    }
                }
            }
            onEntity(roles, fn, email)
            walkEntities(e.optJSONArray("entities"), onEntity)
        }
    }

    private fun rirFrom(o: JSONObject): String? {
        val hint = o.optStringOrNull("port43")
            ?: o.optJSONArray("links")?.optJSONObject(0)?.optStringOrNull("href")
            ?: o.optJSONArray("notices")?.optJSONObject(0)?.optStringOrNull("title")
            ?: return null
        val h = hint.lowercase()
        return when {
            "arin" in h -> "ARIN"
            "ripe" in h -> "RIPE NCC"
            "apnic" in h -> "APNIC"
            "lacnic" in h -> "LACNIC"
            "afrinic" in h -> "AFRINIC"
            else -> null
        }
    }

    private fun isLocalV6(s: String): Boolean {
        val t = s.trim().lowercase()
        return t == "::1" || t.startsWith("fe80") || t.startsWith("fc") || t.startsWith("fd")
    }

    // --- HTTP -----------------------------------------------------------------

    private fun httpGet(url: String, timeoutMs: Int): String? {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = timeoutMs; readTimeout = timeoutMs
                requestMethod = "GET"
                instanceFollowRedirects = true
                setRequestProperty("Accept", "application/json, application/rdap+json")
                setRequestProperty("User-Agent", UA)
            }
            val code = conn.responseCode
            if (code !in 200..299) Log.w(TAG, "GET $url -> HTTP $code")
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream ?: return null
            stream.bufferedReader().use { it.readText() }.takeIf { it.isNotBlank() }
        } catch (e: Exception) {
            // Swallowing this silently made a failing lookup indistinguishable from an
            // address with no known location, which is why the traffic map could come
            // back empty with nothing to show for it. Log, then degrade as before.
            Log.w(TAG, "GET $url failed: ${e.javaClass.simpleName}: ${e.message}")
            null
        } finally { conn?.disconnect() }
    }

    // --- JSON helpers (null instead of "null"/empty) --------------------------

    private fun JSONObject.optStringOrNull(key: String): String? =
        if (has(key) && !isNull(key)) optString(key).trim().ifBlank { null } else null

    private fun JSONObject.optDoubleOrNull(key: String): Double? =
        if (has(key) && !isNull(key)) optDouble(key).takeIf { !it.isNaN() } else null
}

package dev.alsatianconsulting.pocketpcap.resolve

/**
 * GeoIP + WHOIS/RDAP details for a public endpoint. Fields are nullable because the
 * two upstream sources are independent and either may be unavailable.
 */
data class EndpointLocation(
    val address: String,
    val isPrivate: Boolean = false,
    // GeoIP (ipwho.is)
    val country: String? = null,
    val countryCode: String? = null,
    val region: String? = null,
    val city: String? = null,
    val postal: String? = null,
    val latitude: Double? = null,
    val longitude: Double? = null,
    val flagEmoji: String? = null,
    val timezone: String? = null,
    val geoSource: String? = null,
    // Network / autonomous system
    val asn: String? = null,        // e.g. "AS15169"
    val org: String? = null,
    val isp: String? = null,
    // WHOIS / RDAP registration
    val netName: String? = null,
    val cidr: String? = null,
    val registrant: String? = null,
    val rdapCountry: String? = null,
    val abuseEmail: String? = null,
    val rir: String? = null,        // ARIN / RIPE / APNIC / LACNIC / AFRINIC
    val error: String? = null,
) {
    val hasGeo: Boolean get() = country != null || city != null || latitude != null
    val hasWhois: Boolean get() = netName != null || cidr != null || registrant != null || abuseEmail != null
    val hasAny: Boolean get() = hasGeo || hasWhois || asn != null || org != null
}

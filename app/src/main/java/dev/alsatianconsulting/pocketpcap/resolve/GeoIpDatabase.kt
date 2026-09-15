package dev.alsatianconsulting.pocketpcap.resolve

import java.math.BigInteger
import java.net.InetAddress

data class GeoIpDatabaseInfo(
    val fileName: String = "",
    val recordCount: Int = 0,
    val importedAt: Long = 0L,
    val error: String? = null,
) {
    val hasDatabase: Boolean get() = fileName.isNotBlank() && recordCount > 0
}

data class GeoIpRecord(
    val network: String,
    val start: BigInteger,
    val end: BigInteger,
    val prefixLength: Int,
    val country: String? = null,
    val countryCode: String? = null,
    val region: String? = null,
    val city: String? = null,
    val postal: String? = null,
    val latitude: Double? = null,
    val longitude: Double? = null,
    val timezone: String? = null,
    val asn: String? = null,
    val org: String? = null,
    val isp: String? = null,
)

object GeoIpDatabase {

    fun parseCsv(text: String): List<GeoIpRecord> {
        val lines = text.lineSequence().filter { it.isNotBlank() && !it.trimStart().startsWith("#") }.toList()
        if (lines.isEmpty()) return emptyList()
        val header = parseCsvLine(lines.first()).map { it.trim().lowercase() }
        val index = header.withIndex().associate { it.value to it.index }
        return lines.drop(1).mapNotNull { raw ->
            val row = parseCsvLine(raw)
            val network = value(row, index, "cidr", "network", "ip_prefix", "prefix")
            val startIp = value(row, index, "start_ip", "start", "from")
            val endIp = value(row, index, "end_ip", "end", "to")
            val range = when {
                !network.isNullOrBlank() -> parseNetwork(network)
                !startIp.isNullOrBlank() && !endIp.isNullOrBlank() -> parseRange(startIp, endIp)
                else -> null
            } ?: return@mapNotNull null
            GeoIpRecord(
                network = network ?: "$startIp-$endIp",
                start = range.start,
                end = range.end,
                prefixLength = range.prefixLength,
                country = value(row, index, "country", "country_name"),
                countryCode = value(row, index, "country_code", "country_iso_code", "iso_code"),
                region = value(row, index, "region", "subdivision", "state"),
                city = value(row, index, "city"),
                postal = value(row, index, "postal", "postal_code", "zip"),
                latitude = value(row, index, "latitude", "lat")?.toDoubleOrNull(),
                longitude = value(row, index, "longitude", "lon", "lng")?.toDoubleOrNull(),
                timezone = value(row, index, "timezone", "time_zone"),
                asn = value(row, index, "asn")?.let { if (it.startsWith("AS", true)) it.uppercase() else "AS$it" },
                org = value(row, index, "org", "organization", "organisation"),
                isp = value(row, index, "isp"),
            )
        }.sortedWith(compareByDescending<GeoIpRecord> { it.prefixLength }.thenBy { it.start })
    }

    fun lookup(records: List<GeoIpRecord>, address: String): EndpointLocation? {
        val ip = ipToBigInteger(address) ?: return null
        val record = records.firstOrNull { ip >= it.start && ip <= it.end } ?: return null
        return EndpointLocation(
            address = address,
            country = record.country,
            countryCode = record.countryCode,
            region = record.region,
            city = record.city,
            postal = record.postal,
            latitude = record.latitude,
            longitude = record.longitude,
            timezone = record.timezone,
            asn = record.asn,
            org = record.org,
            isp = record.isp,
            geoSource = "Offline custom database (${record.network})",
        )
    }

    private data class IpRange(val start: BigInteger, val end: BigInteger, val prefixLength: Int)

    private fun parseNetwork(cidr: String): IpRange? {
        val parts = cidr.trim().split("/", limit = 2)
        val base = ipToBigInteger(parts[0]) ?: return null
        val bytes = runCatching { InetAddress.getByName(parts[0]).address.size }.getOrNull() ?: return null
        val bits = bytes * 8
        val prefix = parts.getOrNull(1)?.toIntOrNull()?.coerceIn(0, bits) ?: bits
        val hostBits = bits - prefix
        val size = BigInteger.ONE.shiftLeft(hostBits)
        val start = base.shiftRight(hostBits).shiftLeft(hostBits)
        return IpRange(start, start + size - BigInteger.ONE, prefix)
    }

    private fun parseRange(start: String, end: String): IpRange? {
        val s = ipToBigInteger(start) ?: return null
        val e = ipToBigInteger(end) ?: return null
        return if (s <= e) IpRange(s, e, 0) else null
    }

    private fun ipToBigInteger(address: String): BigInteger? =
        runCatching { BigInteger(1, InetAddress.getByName(address.trim()).address) }.getOrNull()

    private fun value(row: List<String>, index: Map<String, Int>, vararg names: String): String? {
        val idx = names.firstNotNullOfOrNull { index[it] } ?: return null
        return row.getOrNull(idx)?.trim()?.ifBlank { null }
    }

    private fun parseCsvLine(line: String): List<String> {
        val out = mutableListOf<String>()
        val cur = StringBuilder()
        var quoted = false
        var i = 0
        while (i < line.length) {
            val c = line[i]
            when {
                c == '"' && quoted && i + 1 < line.length && line[i + 1] == '"' -> {
                    cur.append('"'); i++
                }
                c == '"' -> quoted = !quoted
                c == ',' && !quoted -> {
                    out += cur.toString()
                    cur.setLength(0)
                }
                else -> cur.append(c)
            }
            i++
        }
        out += cur.toString()
        return out
    }
}

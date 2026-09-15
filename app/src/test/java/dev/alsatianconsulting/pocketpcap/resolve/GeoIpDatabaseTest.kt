package dev.alsatianconsulting.pocketpcap.resolve

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GeoIpDatabaseTest {

    @Test fun parsesCsvAndUsesMostSpecificCidr() {
        val csv = """
            cidr,country,country_code,region,city,latitude,longitude,asn,org,isp
            8.8.0.0/16,United States,US,California,Generic,37.0,-122.0,15169,Google LLC,Google
            8.8.8.0/24,United States,US,California,Mountain View,37.386,-122.0838,AS15169,Google DNS,Google
        """.trimIndent()
        val records = GeoIpDatabase.parseCsv(csv)
        assertEquals(2, records.size)
        val loc = GeoIpDatabase.lookup(records, "8.8.8.8")!!
        assertEquals("Mountain View", loc.city)
        assertEquals("AS15169", loc.asn)
        assertTrue(loc.geoSource!!.startsWith("Offline custom database"))
    }

    @Test fun supportsStartEndRanges() {
        val csv = """
            start_ip,end_ip,country,city
            203.0.113.1,203.0.113.10,Documentation,Example City
        """.trimIndent()
        val records = GeoIpDatabase.parseCsv(csv)
        assertEquals("Example City", GeoIpDatabase.lookup(records, "203.0.113.5")!!.city)
        assertNull(GeoIpDatabase.lookup(records, "203.0.113.20"))
    }
}

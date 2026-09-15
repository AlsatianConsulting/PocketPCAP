package dev.alsatianconsulting.pocketpcap.resolve

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Parser tests for the GeoIP (ipwho.is) and WHOIS (RDAP) responses. */
class LocationLookupTest {

    private val geoJson = """
        {"ip":"8.8.8.8","success":true,"country":"United States","country_code":"US",
         "region":"California","city":"Mountain View","latitude":37.386,"longitude":-122.0838,
         "postal":"94039","flag":{"emoji":"US"},
         "connection":{"asn":15169,"org":"Google LLC","isp":"Google LLC","domain":"google.com"},
         "timezone":{"id":"America/Los_Angeles"}}
    """.trimIndent()

    private val rdapJson = """
        {"name":"GOGL","country":"US",
         "cidr0_cidrs":[{"v4prefix":"8.8.8.0","length":24}],
         "startAddress":"8.8.8.0","endAddress":"8.8.8.255","port43":"whois.arin.net",
         "entities":[
           {"roles":["registrant"],
            "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Google LLC"]]],
            "entities":[
              {"roles":["abuse"],
               "vcardArray":["vcard",[["fn",{},"text","Abuse"],["email",{},"text","network-abuse@google.com"]]]}
            ]}
         ]}
    """.trimIndent()

    @Test fun parseGeo_extractsLocationAndAsn() {
        val g = LocationLookup.parseGeo("8.8.8.8", geoJson)!!
        assertEquals("United States", g.country)
        assertEquals("US", g.countryCode)
        assertEquals("Mountain View", g.city)
        assertEquals("California", g.region)
        assertEquals("AS15169", g.asn)
        assertEquals("Google LLC", g.org)
        assertEquals("America/Los_Angeles", g.timezone)
        assertNotNull(g.latitude); assertTrue(g.latitude!! > 37.0 && g.latitude!! < 38.0)
        assertTrue(g.hasGeo)
    }

    @Test fun parseGeo_failureSetsError() {
        val g = LocationLookup.parseGeo("0.0.0.0", """{"success":false,"message":"Invalid IP address"}""")!!
        assertEquals("Invalid IP address", g.error)
        assertNull(g.country)
    }

    @Test fun parseRdap_extractsRegistration() {
        val r = LocationLookup.parseRdap("8.8.8.8", rdapJson)!!
        assertEquals("GOGL", r.netName)
        assertEquals("8.8.8.0/24", r.cidr)
        assertEquals("Google LLC", r.registrant)
        assertEquals("network-abuse@google.com", r.abuseEmail)
        assertEquals("ARIN", r.rir)
        assertTrue(r.hasWhois)
    }

    @Test fun merge_combinesBothSources() {
        val merged = LocationLookup.merge(
            "8.8.8.8",
            LocationLookup.parseGeo("8.8.8.8", geoJson),
            LocationLookup.parseRdap("8.8.8.8", rdapJson),
        )
        assertEquals("Mountain View", merged.city)     // from geo
        assertEquals("GOGL", merged.netName)           // from rdap
        assertEquals("network-abuse@google.com", merged.abuseEmail)
        assertTrue(merged.hasGeo && merged.hasWhois)
    }

    @Test fun merge_bothNullIsError() {
        val merged = LocationLookup.merge("8.8.8.8", null, null)
        assertNotNull(merged.error)
        assertTrue(!merged.hasAny)
    }
}

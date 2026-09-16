package dev.alsatianconsulting.pocketpcap.resolve

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Online endpoint lookups are opt-in, and the gate lives in [LocationLookup] rather than
 * in the UI so no caller can route around it. These run with no network available in the
 * JVM, so a lookup that tried to reach out would fail rather than return the offline
 * record - which is exactly what makes the assertions meaningful.
 */
class LocationLookupConsentTest {

    private val offline = EndpointLocation(
        address = "104.18.66.57",
        city = "San Francisco",
        country = "United States",
        latitude = 37.77,
        longitude = -122.42,
    )

    @Test
    fun withConsentWithheldTheOfflineRecordIsUsedAsIs() = runBlocking {
        val loc = LocationLookup.lookup("104.18.66.57", offlineGeo = offline, allowOnline = false)
        assertEquals("San Francisco", loc.city)
        assertEquals(37.77, loc.latitude!!, 0.001)
    }

    /** No offline data and no consent must yield nothing, never a network attempt. */
    @Test
    fun withConsentWithheldAndNoOfflineDataNothingIsResolved() = runBlocking {
        val loc = LocationLookup.lookup("104.18.66.57", offlineGeo = null, allowOnline = false)
        assertNull(loc.city)
        assertNull(loc.latitude)
        assertNull(loc.org)
    }

    /** Private space is short-circuited before consent even matters. */
    @Test
    fun privateAddressesAreNeverLookedUpEitherWay() = runBlocking {
        for (allow in listOf(true, false)) {
            val loc = LocationLookup.lookup("10.0.0.9", allowOnline = allow)
            assertEquals(true, loc.isPrivate)
        }
    }
}

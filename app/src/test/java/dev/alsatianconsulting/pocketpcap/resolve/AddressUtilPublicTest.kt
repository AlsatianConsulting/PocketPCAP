package dev.alsatianconsulting.pocketpcap.resolve

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The traffic map asks a third party about every address this returns true for, so a
 * wrong answer here is both a wasted lookup and a needless disclosure. The multicast and
 * broadcast cases are the ones that actually leaked: 224.0.0.251, 239.255.255.250,
 * 255.255.255.255 and 0.0.0.0 were all being sent to rdap.org, which can only 404.
 */
class AddressUtilPublicTest {

    @Test fun routableUnicastIsPublic() {
        listOf("104.18.66.57", "8.8.8.8", "1.1.1.1", "167.82.49.55",
               "2606:4700::1111", "2a00:1450:4001:80e::200e").forEach {
            assertTrue("$it should be public", AddressUtil.isPublicRoutable(it))
        }
    }

    @Test fun multicastAndBroadcastAreNotPublic() {
        listOf("224.0.0.251", "224.0.0.22", "239.255.255.250", "255.255.255.255",
               "ff02::fb", "ff02::1:ff64:f8e2").forEach {
            assertFalse("$it must not be looked up", AddressUtil.isPublicRoutable(it))
        }
    }

    @Test fun privateLoopbackAndLinkLocalAreNotPublic() {
        listOf("10.0.0.9", "192.168.1.1", "172.16.0.1", "169.254.1.1", "127.0.0.1",
               "0.0.0.0", "100.64.0.1", "fe80::1", "fd05:275e::1", "::1", "::").forEach {
            assertFalse("$it must not be looked up", AddressUtil.isPublicRoutable(it))
        }
    }

    @Test fun documentationAndTestRangesAreNotPublic() {
        listOf("192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1", "2001:db8::1").forEach {
            assertFalse("$it must not be looked up", AddressUtil.isPublicRoutable(it))
        }
    }

    @Test fun nonAddressesAreNotPublic() {
        listOf("", "not-an-ip", "10.0.0", "999.1.1.1", "aa:bb:cc:dd:ee:ff").forEach {
            assertFalse("$it must not be looked up", AddressUtil.isPublicRoutable(it))
        }
    }

    /** A zone-suffixed link-local still has to be rejected. */
    @Test fun zoneSuffixedLinkLocalIsNotPublic() {
        assertFalse(AddressUtil.isPublicRoutable("fe80::1%wlan0"))
    }
}

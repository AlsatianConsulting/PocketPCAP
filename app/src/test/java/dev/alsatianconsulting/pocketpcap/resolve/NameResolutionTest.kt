package dev.alsatianconsulting.pocketpcap.resolve

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NameResolutionTest {

    // Wireshark `manuf`-style sample: 24-bit (MA-L), 28-bit (MA-M), 36-bit (MA-S),
    // plus a legacy space-separated row.
    private val sampleOui = """
        # comment
        00:0C:29	VMware	VMware, Inc.
        00:55:DA:20/28	ConnectedInf	Beijing Connected Information Technology Co.,Ltd.
        00:1B:C5:00:00/36	Converging	Converging Systems Inc.
        B827EB Raspberry Pi
    """.trimIndent()

    @Test fun oui_parseAndLookup_maL() {
        val table = OuiTable.parse(sampleOui.lineSequence())
        assertEquals("VMware, Inc.", OuiTable.lookup(table, "00:0C:29:AA:BB:CC"))
        assertEquals("Raspberry Pi", OuiTable.lookup(table, "B8-27-EB-12-34-56"))
        assertNull(OuiTable.lookup(table, "FF:FF:FF:00:00:00"))
    }

    @Test fun oui_extendedBlocks_maM_and_maS() {
        val table = OuiTable.parse(sampleOui.lineSequence())
        // 28-bit MA-M: 00:55:DA:2x → ConnectedInf
        assertEquals("Beijing Connected Information Technology Co.,Ltd.",
            OuiTable.lookup(table, "00:55:DA:2F:11:22"))
        // 36-bit MA-S: 00:1B:C5:00:0x → Converging
        assertEquals("Converging Systems Inc.",
            OuiTable.lookup(table, "00:1B:C5:00:0A:BB"))
        // A different sub-block of the same /24 must not match the MA-S vendor.
        assertNull(OuiTable.lookup(table, "00:1B:C5:FF:FF:FF"))
    }

    @Test fun oui_mostSpecificWins() {
        // /24 vendor and a more specific /28 carve-out within it.
        val table = OuiTable.parse(sequenceOf(
            "AA:BB:CC\tBroadVendor\tBroad Vendor Inc.",
            "AA:BB:CC:50/28\tNarrowVendor\tNarrow Vendor LLC",
        ))
        assertEquals("Narrow Vendor LLC", OuiTable.lookup(table, "AA:BB:CC:5A:00:00"))
        assertEquals("Broad Vendor Inc.", OuiTable.lookup(table, "AA:BB:CC:10:00:00"))
    }

    @Test fun addressUtil_classifies() {
        assertTrue(AddressUtil.isMacAddress("AA:BB:CC:DD:EE:FF"))
        assertTrue(AddressUtil.isMacAddress("aa-bb-cc-dd-ee-ff"))
        assertFalse(AddressUtil.isMacAddress("192.168.1.1"))
        assertTrue(AddressUtil.isIpv4("192.168.1.1"))
        assertFalse(AddressUtil.isIpv4("999.1.1.1"))
        assertTrue(AddressUtil.isIpv6("fe80::1"))
    }

    @Test fun addressUtil_privateIpv4() {
        assertTrue(AddressUtil.isPrivateIpv4("192.168.1.5"))
        assertTrue(AddressUtil.isPrivateIpv4("10.0.0.5"))
        assertTrue(AddressUtil.isPrivateIpv4("172.16.0.1"))
        assertTrue(AddressUtil.isPrivateIpv4("172.31.255.254"))
        assertTrue(AddressUtil.isPrivateIpv4("169.254.1.1"))
        assertFalse(AddressUtil.isPrivateIpv4("8.8.8.8"))
        assertFalse(AddressUtil.isPrivateIpv4("172.32.0.1"))
        assertFalse(AddressUtil.isPrivateIpv4("AA:BB:CC:DD:EE:FF"))
    }

    @Test fun addressUtil_fieldSelection() {
        assertEquals("ip.addr", AddressUtil.addrField("8.8.8.8"))
        assertEquals("eth.addr", AddressUtil.addrField("AA:BB:CC:DD:EE:FF"))
        assertEquals("ip.src", AddressUtil.srcField("8.8.8.8"))
        assertEquals("eth.dst", AddressUtil.dstField("AA:BB:CC:DD:EE:FF"))
    }

    @Test fun nameFormat_respectsDisplayMode() {
        val resolved = ResolvedName("192.168.1.15", "Geoff-MacBook", NameSource.ALIAS)
        assertEquals(
            EndpointLabel("192.168.1.15", null),
            NameFormat.label(resolved, ResolveDisplayMode.ADDRESS),
        )
        assertEquals(
            EndpointLabel("Geoff-MacBook", null),
            NameFormat.label(resolved, ResolveDisplayMode.NAME),
        )
        assertEquals(
            EndpointLabel("Geoff-MacBook", "192.168.1.15"),
            NameFormat.label(resolved, ResolveDisplayMode.NAME_ADDRESS),
        )
    }

    @Test fun nameFormat_fallsBackToAddressWhenNoName() {
        val resolved = ResolvedName("10.0.0.5", null, NameSource.NONE)
        assertEquals(
            EndpointLabel("10.0.0.5", null),
            NameFormat.label(resolved, ResolveDisplayMode.NAME_ADDRESS),
        )
    }
}

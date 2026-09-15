package dev.alsatianconsulting.pocketpcap.resolve

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.zip.GZIPInputStream

/**
 * End-to-end check of the bundled OUI asset: opens `assets/manuf.bin` through the real
 * app context, decompresses, parses, and resolves known vendors — proving the asset is
 * packaged under the expected name (the Android build must not have gunzipped/renamed
 * it) and that the full table including extended MA-M/MA-S blocks loads.
 */
@RunWith(AndroidJUnit4::class)
class OuiAssetTest {

    private fun loadBundledOui(): OuiData {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        ctx.assets.open("manuf.bin").use { raw ->
            GZIPInputStream(raw).bufferedReader().use { return OuiTable.parse(it.lineSequence()) }
        }
    }

    @Test
    fun bundledTableLoadsAndResolvesKnownVendors() {
        val oui = loadBundledOui()
        // The full IEEE registry is tens of thousands of entries.
        assertTrue("expected a large OUI table, got ${oui.size}", oui.size > 30_000)
        // Extended blocks must be present.
        assertTrue("expected MA-M (28-bit) blocks", oui.m28.isNotEmpty())
        assertTrue("expected MA-S (36-bit) blocks", oui.m36.isNotEmpty())

        // Well-known MA-L vendors.
        assertEquals("Cisco Systems, Inc", OuiTable.lookup(oui, "00:00:0C:11:22:33"))
        assertNotNull(OuiTable.lookup(oui, "00:50:56:AA:BB:CC"))   // VMware
        assertNotNull(OuiTable.lookup(oui, "B8:27:EB:00:00:01"))   // Raspberry Pi
    }
}

package dev.alsatianconsulting.pocketpcap.data

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Aliases, recent filters and saved filters must survive an app relaunch. We model a
 * relaunch by closing the file-backed database and reopening it.
 */
@RunWith(AndroidJUnit4::class)
class PersistenceTest {

    private val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val dbName = "persist-test"

    private fun open() = Room.databaseBuilder(ctx, PocketPcapDatabase::class.java, dbName)
        .addMigrations(*PocketPcapDatabase.ALL_MIGRATIONS)
        .build()

    @Test
    fun dataSurvivesReopen() = runBlocking<Unit> {
        ctx.deleteDatabase(dbName)
        var db = open()
        db.endpointAliasDao().upsert(EndpointAliasEntity("aa:bb:cc:dd:ee:ff", "Work Laptop", 1))
        db.savedFilterDao().insert(SavedFilterEntity(name = "DNS only", filter = "dns", createdAt = 1))
        db.recentFilterDao().upsert(RecentFilterEntity("tcp.port == 443", 1))
        db.analysisBookmarkDao().insert(AnalysisBookmarkEntity(
            capturePath = "/capture.pcap", type = "PACKET", referenceId = "42",
            label = "Packet 42", note = "Investigate", filter = "frame.number == 42",
            packetNumber = 42, createdAt = 1,
        ))
        db.close()

        // Reopen — simulates a fresh launch.
        db = open()
        assertEquals("Work Laptop", db.endpointAliasDao().get("aa:bb:cc:dd:ee:ff")?.name)
        assertEquals(1, db.savedFilterDao().getAll().size)
        assertTrue(db.recentFilterDao().recent(20).any { it.filter == "tcp.port == 443" })
        assertEquals("Investigate", db.analysisBookmarkDao().forCapture("/capture.pcap").single().note)

        // Editing + removal works and persists.
        db.endpointAliasDao().upsert(EndpointAliasEntity("aa:bb:cc:dd:ee:ff", "My Laptop", 2))
        assertEquals("My Laptop", db.endpointAliasDao().get("aa:bb:cc:dd:ee:ff")?.name)
        db.endpointAliasDao().delete("aa:bb:cc:dd:ee:ff")
        assertNull(db.endpointAliasDao().get("aa:bb:cc:dd:ee:ff"))
        db.close()
        ctx.deleteDatabase(dbName)
    }

    @Test
    fun recentFiltersTrimToCap() = runBlocking<Unit> {
        ctx.deleteDatabase(dbName)
        val db = open()
        for (i in 1..30) {
            db.recentFilterDao().upsert(RecentFilterEntity("filter_$i", i.toLong()))
        }
        db.recentFilterDao().trimTo(20)
        val kept = db.recentFilterDao().recent(100)
        assertEquals(20, kept.size)
        // The newest survive; the oldest are trimmed.
        assertTrue(kept.any { it.filter == "filter_30" })
        assertTrue(kept.none { it.filter == "filter_1" })
        db.close()
        ctx.deleteDatabase(dbName)
    }
}

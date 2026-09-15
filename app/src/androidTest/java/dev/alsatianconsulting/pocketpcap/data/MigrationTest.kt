package dev.alsatianconsulting.pocketpcap.data

import androidx.room.testing.MigrationTestHelper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.IOException

/**
 * Verifies all Room migrations are additive and preserve existing user data.
 */
@RunWith(AndroidJUnit4::class)
class MigrationTest {

    private val testDb = "migration-test"

    @get:Rule
    val helper = MigrationTestHelper(
        InstrumentationRegistry.getInstrumentation(),
        PocketPcapDatabase::class.java,
    )

    @Test
    @Throws(IOException::class)
    fun migrate1To2_preservesDataAndAddsSavedFilters() {
        // Seed a v1 database.
        helper.createDatabase(testDb, 1).apply {
            execSQL("INSERT INTO endpoint_aliases (address, name, updatedAt) VALUES ('192.168.1.1', 'Home Router', 100)")
            execSQL("INSERT INTO recent_filters (filter, usedAt) VALUES ('dns', 200)")
            close()
        }

        // Run the real migration and validate the schema matches v2.
        val db = helper.runMigrationsAndValidate(
            testDb, 2, true, PocketPcapDatabase.MIGRATION_1_2
        )

        // Existing user data preserved.
        db.query("SELECT name FROM endpoint_aliases WHERE address = '192.168.1.1'").use { c ->
            assertTrue(c.moveToFirst())
            assertEquals("Home Router", c.getString(0))
        }
        db.query("SELECT usedAt FROM recent_filters WHERE filter = 'dns'").use { c ->
            assertTrue(c.moveToFirst())
            assertEquals(200, c.getInt(0))
        }

        // New saved_filters table is present and writable.
        db.execSQL("INSERT INTO saved_filters (name, filter, createdAt) VALUES ('TLS', 'tls', 300)")
        db.query("SELECT count(*) FROM saved_filters").use { c ->
            assertTrue(c.moveToFirst())
            assertEquals(1, c.getInt(0))
        }
    }

    @Test
    @Throws(IOException::class)
    fun migrate2To3_preservesDataAndAddsAnalysisBookmarks() {
        helper.createDatabase(testDb, 2).apply {
            execSQL("INSERT INTO saved_filters (name, filter, createdAt) VALUES ('TLS', 'tls', 300)")
            close()
        }
        val db = helper.runMigrationsAndValidate(testDb, 3, true, PocketPcapDatabase.MIGRATION_2_3)
        db.query("SELECT filter FROM saved_filters WHERE name = 'TLS'").use { c ->
            assertTrue(c.moveToFirst())
            assertEquals("tls", c.getString(0))
        }
        db.execSQL(
            "INSERT INTO analysis_bookmarks (capturePath,type,referenceId,label,note,filter,packetNumber,createdAt) " +
                "VALUES ('/capture.pcap','PACKET','42','Packet 42','Investigate','frame.number == 42',42,400)"
        )
        db.query("SELECT note FROM analysis_bookmarks").use { c ->
            assertTrue(c.moveToFirst())
            assertEquals("Investigate", c.getString(0))
        }
    }
}

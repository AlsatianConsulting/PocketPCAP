package dev.alsatianconsulting.pocketpcap.storage

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * The whole point of [SharedCaptureStore] is that a file in `Documents/pocketpcap` can
 * afterwards be written and read with ordinary `File` APIs, because that is how dumpcap
 * and the tunnel recorder write and how tshark reads. Direct `File` creation there is
 * refused under scoped storage, so this asserts the part that is not obvious: that going
 * through MediaStore first buys back plain file access on the real path.
 *
 * [SharedCaptureStoreTargetTest] covers which directories take that route; this covers
 * what happens once they do.
 */
@RunWith(AndroidJUnit4::class)
class SharedCaptureStoreTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val shared = SharedCaptureStore.directory()
    private val created = mutableListOf<File>()

    @After
    fun cleanUp() {
        created.forEach { SharedCaptureStore.forget(context, it); it.delete() }
    }

    private fun create(name: String): File =
        SharedCaptureStore.newFile(context, shared, name)!!.also { created += it }

    @Test
    fun createsAFileUnderDocumentsPocketpcap() {
        val file = create("test_${System.currentTimeMillis()}.pcapng")
        assertTrue(
            "not under Documents/pocketpcap: $file",
            file.absolutePath.contains("/Documents/${SharedCaptureStore.FOLDER}/"),
        )
        assertTrue("does not exist: $file", file.exists())
    }

    /** The bit that direct File access cannot do: write, then read it straight back. */
    @Test
    fun theFileIsReadableAndWritableThroughPlainFileApis() {
        val file = create("rw_${System.currentTimeMillis()}.pcapng")
        val payload = ByteArray(4096) { (it % 251).toByte() }
        file.writeBytes(payload)
        assertEquals(payload.size.toLong(), file.length())
        assertTrue("bytes did not survive the round trip", file.readBytes().contentEquals(payload))
    }

    /**
     * Asking twice for one name must give one file. MediaStore's default is to invent
     * "name (1)", which would send a capture somewhere the caller never asked for.
     */
    @Test
    fun reusesTheExistingRowInsteadOfInventingASuffixedName() {
        val name = "dup_${System.currentTimeMillis()}.pcapng"
        val first = create(name)
        val second = SharedCaptureStore.newFile(context, shared, name)
        assertEquals(first.absolutePath, second?.absolutePath)
        assertEquals(name, first.name)
    }

    /**
     * An export declares its own type, and MediaStore appends the extension it would
     * have chosen when that disagrees with the name. A mismatch would land the file at
     * `foo.csv.bin` while the caller wrote to `foo.csv`.
     */
    @Test
    fun keepsTheNameForNonCaptureExportTypes() {
        val name = "table_${System.currentTimeMillis()}.csv"
        val file = create(name)
        assertEquals(name, file.name)
        file.writeText("a,b\n1,2\n")
        assertEquals("a,b\n1,2\n", file.readText())
    }

    @Test
    fun listsTheFilesItCreated() {
        val file = create("listed_${System.currentTimeMillis()}.pcapng")
        file.writeBytes(ByteArray(16))
        val listed = SharedCaptureStore.listFiles(context, shared).map { it.absolutePath }
        assertTrue("$file missing from $listed", file.absolutePath in listed)
    }

    /**
     * Repeated on purpose. Recreating a name that was just deleted intermittently came
     * back EACCES on a file that existed and that MediaStore already named us the owner
     * of - a stale FUSE access decision outliving the deleted file - which showed up
     * here as roughly one failure in twenty-five. [SharedCaptureStore] retries the write
     * probe for that reason, so one pass through this would mostly pass either way.
     */
    @Test
    fun forgetRemovesTheRowSoTheNameIsFreeAgain() {
        repeat(10) {
            val name = "recycled_${System.nanoTime()}.pcapng"
            val first = SharedCaptureStore.newFile(context, shared, name)
            assertNotNull(first)
            SharedCaptureStore.forget(context, first!!)
            first.delete()
            val again = SharedCaptureStore.newFile(context, shared, name)
            assertNotNull("could not recreate $name after forget", again)
            created += again!!
            assertEquals("name was suffixed after forget", name, again.name)
        }
    }

    /**
     * App-private storage takes the ordinary path: no MediaStore row, a real mkdir, and
     * the same `File` contract, so the capture fallback behaves identically.
     */
    @Test
    fun appPrivateDirectoriesAreCreatedDirectly() {
        val dir = File(context.getExternalFilesDir(null), "captures/nested_${System.currentTimeMillis()}")
        val file = SharedCaptureStore.newFile(context, dir, "fallback.pcapng")
        assertNotNull("app-private file was not created", file)
        file!!.writeBytes(ByteArray(8))
        assertTrue(file.exists())
        assertTrue(
            "$file missing from its own directory listing",
            file.absolutePath in SharedCaptureStore.listFiles(context, dir).map { it.absolutePath },
        )
        file.delete()
        dir.delete()
    }
}

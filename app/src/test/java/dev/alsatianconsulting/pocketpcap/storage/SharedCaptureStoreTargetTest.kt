package dev.alsatianconsulting.pocketpcap.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The classification that decides whether a directory is written through MediaStore or
 * with ordinary file APIs. Getting it wrong either way is silent: classify app-private
 * storage as shared and every capture goes through a provider that will not take it;
 * classify Documents/pocketpcap as ordinary and the mkdir fails with EACCES and the
 * capture has nowhere to go.
 *
 * This is deliberately plain string arithmetic so it can be exercised here rather than
 * only on a device; [SharedCaptureStoreTest] covers the MediaStore half.
 */
class SharedCaptureStoreTargetTest {

    private fun target(path: String) = SharedCaptureStore.targetFor(path)

    @Test
    fun theDefaultCaptureFolderIsAddressable() {
        val t = target("/storage/emulated/0/Documents/pocketpcap")
        assertEquals("external_primary", t?.volume)
        assertEquals("Documents/pocketpcap/", t?.relativePath)
    }

    @Test
    fun aTrailingSlashDoesNotChangeTheAnswer() {
        assertEquals(
            target("/storage/emulated/0/Documents/pocketpcap")?.relativePath,
            target("/storage/emulated/0/Documents/pocketpcap/")?.relativePath,
        )
    }

    /** MediaStore stores the path with a trailing separator, but queries have to match both. */
    @Test
    fun bothRelativePathFormsAreOffered() {
        val forms = target("/storage/emulated/0/Download/pcaps")!!.relativePathForms
        assertEquals(listOf("Download/pcaps/", "Download/pcaps"), forms.toList())
    }

    @Test
    fun aTopLevelMediaDirectoryIsAddressableOnItsOwn() {
        assertEquals("Documents/", target("/storage/emulated/0/Documents")?.relativePath)
    }

    @Test
    fun nestedFoldersUnderAMediaDirectoryAreAddressable() {
        assertEquals(
            "Documents/pocketpcap/jobs/2026/",
            target("/storage/emulated/0/Documents/pocketpcap/jobs/2026")?.relativePath,
        )
    }

    /** Emulated storage is per-user; a work profile is not user 0 and still primary. */
    @Test
    fun aSecondaryUserVolumeIsStillPrimaryExternal() {
        val t = target("/storage/emulated/10/Documents/pocketpcap")
        assertEquals("external_primary", t?.volume)
        assertEquals("Documents/pocketpcap/", t?.relativePath)
    }

    @Test
    fun aRemovableVolumeIsNamedAfterItsLowercasedUuid() {
        val t = target("/storage/1A2B-3C4D/Movies/pcaps")
        assertEquals("1a2b-3c4d", t?.volume)
        assertEquals("Movies/pcaps/", t?.relativePath)
    }

    /** The important negative: app-private storage is written directly, never through MediaStore. */
    @Test
    fun appPrivateStorageIsNotAddressable() {
        assertNull(
            target("/storage/emulated/0/Android/data/dev.alsatianconsulting.pocketpcap/files/captures")
        )
    }

    @Test
    fun aFolderOutsideTheStandardMediaDirectoriesIsNotAddressable() {
        assertNull(target("/storage/emulated/0/MyCaptures"))
    }

    @Test
    fun theVolumeRootItselfIsNotAddressable() {
        assertNull(target("/storage/emulated/0"))
        assertNull(target("/storage/1A2B-3C4D"))
    }

    @Test
    fun aPathOutsideExternalStorageIsNotAddressable() {
        assertNull(target("/data/local/tmp"))
        assertNull(target("/sdcard/Documents/pocketpcap"))
    }

    @Test
    fun aDirectoryNameThatMerelyStartsWithAMediaDirectoryIsNotAddressable() {
        assertNull(target("/storage/emulated/0/Documentsomething/pcaps"))
    }

    @Test
    fun traversalSegmentsAreRejected() {
        assertNull(target("/storage/emulated/0/Documents/../Android/data"))
    }

    // ---- MIME ------------------------------------------------------------

    /**
     * MediaStore appends the extension it would have chosen when the declared type
     * disagrees with the name, so these have to match or files land on a path the
     * caller never asked for.
     */
    @Test
    fun mimeTypesMatchTheExtensionsTheAppWrites() {
        assertEquals("application/octet-stream", SharedCaptureStore.mimeFor("capture.pcapng"))
        assertEquals("application/octet-stream", SharedCaptureStore.mimeFor("capture.pcap"))
        assertEquals("text/csv", SharedCaptureStore.mimeFor("capture_conversations.csv"))
        assertEquals("application/json", SharedCaptureStore.mimeFor("capture_dns.json"))
        assertEquals("application/json", SharedCaptureStore.mimeFor("capture_map.geojson"))
        assertEquals(
            "application/vnd.google-earth.kml+xml",
            SharedCaptureStore.mimeFor("capture_map.KML"),
        )
    }

    @Test
    fun aNameWithNoExtensionFallsBackToOctetStream() {
        assertEquals("application/octet-stream", SharedCaptureStore.mimeFor("capture"))
    }
}

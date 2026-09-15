package dev.alsatianconsulting.pocketpcap.data

import android.content.Context
import kotlinx.coroutines.flow.Flow

/**
 * Single entry point for persisted endpoint aliases, recent filters and saved
 * filters. Keeps address normalisation in one place so lookups are consistent
 * between the resolver, the suggestion engine and the alias-management UI.
 */
class PcapRepository(context: Context) {

    private val db = PocketPcapDatabase.get(context)
    private val aliasDao = db.endpointAliasDao()
    private val recentDao = db.recentFilterDao()
    private val savedDao = db.savedFilterDao()
    private val bookmarkDao = db.analysisBookmarkDao()

    // --- Endpoint aliases -----------------------------------------------------

    val aliases: Flow<List<EndpointAliasEntity>> = aliasDao.observeAll()

    suspend fun allAliases(): List<EndpointAliasEntity> = aliasDao.getAll()

    suspend fun alias(address: String): String? =
        aliasDao.get(normalizeAddress(address))?.name

    suspend fun setAlias(address: String, name: String) {
        val n = name.trim()
        if (n.isEmpty()) { removeAlias(address); return }
        aliasDao.upsert(
            EndpointAliasEntity(normalizeAddress(address), n, System.currentTimeMillis())
        )
    }

    suspend fun removeAlias(address: String) = aliasDao.delete(normalizeAddress(address))

    // --- Recent filters -------------------------------------------------------

    val recentFilters: Flow<List<RecentFilterEntity>> = recentDao.observeRecent(RECENT_CAP)

    suspend fun recordRecentFilter(filter: String) {
        val f = filter.trim()
        if (f.isEmpty()) return
        recentDao.upsert(RecentFilterEntity(f, System.currentTimeMillis()))
        recentDao.trimTo(RECENT_CAP)
    }

    suspend fun clearRecentFilters() = recentDao.clear()

    // --- Saved filters --------------------------------------------------------

    val savedFilters: Flow<List<SavedFilterEntity>> = savedDao.observeAll()

    suspend fun saveFilter(name: String, filter: String): Long {
        val f = filter.trim()
        if (f.isEmpty()) return -1
        val label = name.trim().ifEmpty { f }
        return savedDao.insert(SavedFilterEntity(name = label, filter = f, createdAt = System.currentTimeMillis()))
    }

    suspend fun deleteSavedFilter(id: Long) = savedDao.deleteById(id)

    // --- Analysis bookmarks + notes -----------------------------------------

    fun bookmarks(capturePath: String): Flow<List<AnalysisBookmarkEntity>> =
        bookmarkDao.observeForCapture(capturePath)

    suspend fun bookmarksList(capturePath: String): List<AnalysisBookmarkEntity> =
        bookmarkDao.forCapture(capturePath)

    suspend fun addBookmark(
        capturePath: String,
        type: String,
        referenceId: String,
        label: String,
        note: String,
        filter: String,
        packetNumber: Long?,
    ): Long = bookmarkDao.insert(
        AnalysisBookmarkEntity(
            capturePath = capturePath,
            type = type,
            referenceId = referenceId,
            label = label,
            note = note.trim(),
            filter = filter,
            packetNumber = packetNumber,
            createdAt = System.currentTimeMillis(),
        )
    )

    suspend fun updateBookmarkNote(id: Long, note: String) = bookmarkDao.updateNote(id, note.trim())
    suspend fun deleteBookmark(id: Long) = bookmarkDao.delete(id)

    companion object {
        const val RECENT_CAP = 20

        /** Normalise an endpoint address for use as a stable alias key. */
        fun normalizeAddress(address: String): String = address.trim().lowercase()
    }
}

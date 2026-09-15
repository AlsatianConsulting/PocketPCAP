package dev.alsatianconsulting.pocketpcap.data

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface EndpointAliasDao {
    @Query("SELECT * FROM endpoint_aliases ORDER BY name COLLATE NOCASE ASC")
    fun observeAll(): Flow<List<EndpointAliasEntity>>

    @Query("SELECT * FROM endpoint_aliases")
    suspend fun getAll(): List<EndpointAliasEntity>

    @Query("SELECT * FROM endpoint_aliases WHERE address = :address LIMIT 1")
    suspend fun get(address: String): EndpointAliasEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(alias: EndpointAliasEntity)

    @Query("DELETE FROM endpoint_aliases WHERE address = :address")
    suspend fun delete(address: String)
}

@Dao
interface RecentFilterDao {
    @Query("SELECT * FROM recent_filters ORDER BY usedAt DESC LIMIT :limit")
    fun observeRecent(limit: Int = 20): Flow<List<RecentFilterEntity>>

    @Query("SELECT * FROM recent_filters ORDER BY usedAt DESC LIMIT :limit")
    suspend fun recent(limit: Int = 20): List<RecentFilterEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(filter: RecentFilterEntity)

    @Query("DELETE FROM recent_filters WHERE filter = :filter")
    suspend fun delete(filter: String)

    @Query("DELETE FROM recent_filters")
    suspend fun clear()

    /** Trim the table to the [keep] most-recent rows. */
    @Query(
        "DELETE FROM recent_filters WHERE filter NOT IN " +
            "(SELECT filter FROM recent_filters ORDER BY usedAt DESC LIMIT :keep)"
    )
    suspend fun trimTo(keep: Int)
}

@Dao
interface SavedFilterDao {
    @Query("SELECT * FROM saved_filters ORDER BY createdAt DESC")
    fun observeAll(): Flow<List<SavedFilterEntity>>

    @Query("SELECT * FROM saved_filters ORDER BY createdAt DESC")
    suspend fun getAll(): List<SavedFilterEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(filter: SavedFilterEntity): Long

    @Delete
    suspend fun delete(filter: SavedFilterEntity)

    @Query("DELETE FROM saved_filters WHERE id = :id")
    suspend fun deleteById(id: Long)
}

@Dao
interface AnalysisBookmarkDao {
    @Query("SELECT * FROM analysis_bookmarks WHERE capturePath = :capturePath ORDER BY createdAt DESC")
    fun observeForCapture(capturePath: String): Flow<List<AnalysisBookmarkEntity>>

    @Query("SELECT * FROM analysis_bookmarks WHERE capturePath = :capturePath ORDER BY createdAt DESC")
    suspend fun forCapture(capturePath: String): List<AnalysisBookmarkEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(bookmark: AnalysisBookmarkEntity): Long

    @Query("UPDATE analysis_bookmarks SET note = :note WHERE id = :id")
    suspend fun updateNote(id: Long, note: String)

    @Query("DELETE FROM analysis_bookmarks WHERE id = :id")
    suspend fun delete(id: Long)
}

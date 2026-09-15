package dev.alsatianconsulting.pocketpcap.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * The app's Room database.
 *
 * Version history (all migrations are additive — no destructive fallback):
 *   v1: endpoint_aliases, recent_filters
 *   v2: + saved_filters
 *   v3: + analysis_bookmarks (derived analyst notes; source captures untouched)
 *
 * Schemas are exported to app/schemas and bundled into the androidTest assets so
 * [androidx.room.testing.MigrationTestHelper] can verify every migration preserves
 * existing user data.
 */
@Database(
    entities = [
        EndpointAliasEntity::class,
        RecentFilterEntity::class,
        SavedFilterEntity::class,
        AnalysisBookmarkEntity::class,
    ],
    version = 3,
    exportSchema = true,
)
abstract class PocketPcapDatabase : RoomDatabase() {
    abstract fun endpointAliasDao(): EndpointAliasDao
    abstract fun recentFilterDao(): RecentFilterDao
    abstract fun savedFilterDao(): SavedFilterDao
    abstract fun analysisBookmarkDao(): AnalysisBookmarkDao

    companion object {
        const val DB_NAME = "pocketpcap.db"

        /** v1 → v2: add the saved_filters table. Existing aliases/recents untouched. */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `saved_filters` (" +
                        "`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, " +
                        "`name` TEXT NOT NULL, " +
                        "`filter` TEXT NOT NULL, " +
                        "`createdAt` INTEGER NOT NULL)"
                )
            }
        }

        /** v2 → v3: add capture-scoped bookmarks and analyst notes. */
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `analysis_bookmarks` (" +
                        "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                        "`capturePath` TEXT NOT NULL, " +
                        "`type` TEXT NOT NULL, " +
                        "`referenceId` TEXT NOT NULL, " +
                        "`label` TEXT NOT NULL, " +
                        "`note` TEXT NOT NULL, " +
                        "`filter` TEXT NOT NULL, " +
                        "`packetNumber` INTEGER, " +
                        "`createdAt` INTEGER NOT NULL)"
                )
            }
        }

        val ALL_MIGRATIONS = arrayOf(MIGRATION_1_2, MIGRATION_2_3)

        @Volatile private var instance: PocketPcapDatabase? = null

        fun get(context: Context): PocketPcapDatabase =
            instance ?: synchronized(this) {
                instance ?: build(context).also { instance = it }
            }

        private fun build(context: Context): PocketPcapDatabase =
            Room.databaseBuilder(
                context.applicationContext, PocketPcapDatabase::class.java, DB_NAME
            )
                .addMigrations(*ALL_MIGRATIONS)
                .build()
    }
}

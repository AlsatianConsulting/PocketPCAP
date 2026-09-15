package dev.alsatianconsulting.pocketpcap.data

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * A user-assigned, human-readable name for an endpoint (IP or MAC address).
 * The address is normalised (trimmed, lower-cased) so lookups are stable.
 * Persisted across launches and editable/removable by the user.
 */
@Entity(tableName = "endpoint_aliases")
data class EndpointAliasEntity(
    @PrimaryKey val address: String,
    val name: String,
    val updatedAt: Long,
)

/**
 * A display filter the user has applied. Keyed by the filter text so re-applying an
 * existing filter just bumps its [usedAt]. The most recently used float to the top.
 */
@Entity(tableName = "recent_filters")
data class RecentFilterEntity(
    @PrimaryKey val filter: String,
    val usedAt: Long,
)

/**
 * A named, user-saved display filter (added in DB v2). Survives the recent-filter
 * cap and is meant to be re-applied deliberately.
 */
@Entity(tableName = "saved_filters")
data class SavedFilterEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    val filter: String,
    val createdAt: Long,
)

/** Analyst metadata stored beside a capture; the source PCAP is never modified. */
@Entity(tableName = "analysis_bookmarks")
data class AnalysisBookmarkEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val capturePath: String,
    val type: String,
    val referenceId: String,
    val label: String,
    val note: String,
    val filter: String,
    val packetNumber: Long?,
    val createdAt: Long,
)

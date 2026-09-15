package dev.alsatianconsulting.pocketpcap.update

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

sealed interface UpdateCheckState {
    data object Idle : UpdateCheckState
    data object Checking : UpdateCheckState
    data object UpToDate : UpdateCheckState
    data class Available(
        val currentVersion: String,
        val latestVersion: String,
        val releaseUrl: String,
    ) : UpdateCheckState
    data object Failed : UpdateCheckState
}

/** Explicit, user-triggered GitHub release lookup. No update data is collected or uploaded. */
object UpdateChecker {
    const val REPOSITORY = "AlsatianConsulting/PocketPCAP-dev"
    const val API_URL = "https://api.github.com/repos/$REPOSITORY/releases/latest"
    const val RELEASE_URL = "https://github.com/$REPOSITORY/releases/latest"

    suspend fun check(currentVersion: String): UpdateCheckState = withContext(Dispatchers.IO) {
        var connection: HttpURLConnection? = null
        try {
            connection = (URL(API_URL).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 10_000
                readTimeout = 10_000
                setRequestProperty("Accept", "application/vnd.github+json")
                setRequestProperty("User-Agent", "PocketPCAP/$currentVersion")
                setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
            }
            if (connection.responseCode !in 200..299) return@withContext UpdateCheckState.Failed
            val body = connection.inputStream.bufferedReader().use { it.readText() }
            val release = parseLatestRelease(body)
            if (compareVersions(release.version, currentVersion) > 0) {
                UpdateCheckState.Available(currentVersion, release.version, release.url)
            } else {
                UpdateCheckState.UpToDate
            }
        } catch (_: Exception) {
            UpdateCheckState.Failed
        } finally {
            connection?.disconnect()
        }
    }

    internal data class LatestRelease(val version: String, val url: String)

    internal fun parseLatestRelease(json: String): LatestRelease {
        val value = JSONObject(json)
        val version = value.getString("tag_name").trim().removePrefix("v").removePrefix("V")
        require(version.isNotBlank())
        return LatestRelease(version, value.optString("html_url").ifBlank { RELEASE_URL })
    }

    /** SemVer-style numeric comparison with release builds ordered after prereleases. */
    internal fun compareVersions(left: String, right: String): Int {
        fun parse(value: String): Pair<List<Int>, String?> {
            val normalized = value.trim().removePrefix("v").removePrefix("V").substringBefore('+')
            val core = normalized.substringBefore('-')
            val prerelease = normalized.substringAfter('-', "").ifBlank { null }
            val numbers = core.split('.').map {
                it.takeWhile(Char::isDigit).toIntOrNull()
                    ?: throw IllegalArgumentException("Unsupported version: $value")
            }
            require(numbers.isNotEmpty())
            return numbers to prerelease
        }

        val (leftNumbers, leftPre) = parse(left)
        val (rightNumbers, rightPre) = parse(right)
        repeat(maxOf(leftNumbers.size, rightNumbers.size)) { index ->
            val compared = (leftNumbers.getOrNull(index) ?: 0).compareTo(rightNumbers.getOrNull(index) ?: 0)
            if (compared != 0) return compared
        }
        return when {
            leftPre == null && rightPre != null -> 1
            leftPre != null && rightPre == null -> -1
            leftPre == null -> 0
            else -> leftPre.compareTo(rightPre.orEmpty())
        }
    }
}

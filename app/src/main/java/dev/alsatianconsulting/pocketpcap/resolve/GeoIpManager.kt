package dev.alsatianconsulting.pocketpcap.resolve

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

class GeoIpManager(private val context: Context) {

    private val dir = File(context.filesDir, "geoip").apply { mkdirs() }
    private val dbFile = File(dir, "custom_geoip.csv")
    private val metaFile = File(dir, "custom_geoip.meta")
    @Volatile private var records: List<GeoIpRecord> = emptyList()

    suspend fun load(): GeoIpDatabaseInfo = withContext(Dispatchers.IO) {
        if (!dbFile.exists()) return@withContext GeoIpDatabaseInfo()
        records = GeoIpDatabase.parseCsv(dbFile.readText())
        info()
    }

    suspend fun import(uri: Uri): GeoIpDatabaseInfo = withContext(Dispatchers.IO) {
        val name = queryDisplayName(uri) ?: "custom_geoip.csv"
        val text = context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
            ?: return@withContext GeoIpDatabaseInfo(error = "Could not read the selected GeoIP database.")
        val parsed = GeoIpDatabase.parseCsv(text)
        if (parsed.isEmpty()) {
            return@withContext GeoIpDatabaseInfo(error = "No GeoIP records found. Use CSV with cidr or start_ip/end_ip columns.")
        }
        dbFile.writeText(text)
        metaFile.writeText("${name.replace('\n', ' ')}\n${System.currentTimeMillis()}")
        records = parsed
        info()
    }

    suspend fun clear(): GeoIpDatabaseInfo = withContext(Dispatchers.IO) {
        records = emptyList()
        runCatching { dbFile.delete() }
        runCatching { metaFile.delete() }
        GeoIpDatabaseInfo()
    }

    fun lookup(address: String): EndpointLocation? = GeoIpDatabase.lookup(records, address)

    private fun info(): GeoIpDatabaseInfo {
        val meta = if (metaFile.exists()) metaFile.readLines() else emptyList()
        return GeoIpDatabaseInfo(
            fileName = meta.getOrNull(0).orEmpty().ifBlank { dbFile.name },
            recordCount = records.size,
            importedAt = meta.getOrNull(1)?.toLongOrNull() ?: dbFile.lastModified(),
        )
    }

    private fun queryDisplayName(uri: Uri): String? = try {
        context.contentResolver.query(uri, null, null, null, null)?.use { c ->
            val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
        }
    } catch (_: Exception) { null }
}

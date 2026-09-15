package dev.alsatianconsulting.pocketpcap.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.model.ExportedObject
import dev.alsatianconsulting.pocketpcap.ui.components.*
import dev.alsatianconsulting.pocketpcap.ui.theme.*
import java.io.File

private val OBJECT_TYPES = listOf(
    "http" to "HTTP", "tftp" to "TFTP", "smb" to "SMB", "imf" to "Email", "dicom" to "DICOM",
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ObjectsScreen(
    objects: List<ExportedObject>,
    loading: Boolean,
    selectedType: String,
    onTypeSelected: (String) -> Unit,
    onBack: () -> Unit,
) {
    BackHandler(enabled = true) { onBack() }
    val context = LocalContext.current

    Scaffold(
        containerColor = WarmBg900,
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, "Back", tint = AcOrange500)
                    }
                },
                title = {
                    Column {
                        Eyebrow("Export objects")
                        Text("Reconstructed objects", style = MaterialTheme.typography.titleLarge,
                            color = WarmFgPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Text(
                "Reconstruct files transferred over a protocol, like Wireshark's File → Export Objects.",
                style = MaterialTheme.typography.bodySmall, color = WarmFgMuted,
                modifier = Modifier.padding(16.dp),
            )
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                OBJECT_TYPES.forEach { (k, lbl) ->
                    OutlinedButton(
                        onClick = { onTypeSelected(k) },
                        shape = RoundedCornerShape(6.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = if (selectedType == k) AcOrange500 else WarmFgMuted),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    ) { Text(lbl, style = MaterialTheme.typography.labelMedium) }
                }
            }
            Spacer(Modifier.height(8.dp))

            when {
                loading -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = AcOrange500)
                }
                objects.isEmpty() -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("Pick a protocol above to extract its objects.",
                        style = MaterialTheme.typography.bodyMedium, color = WarmFgMuted)
                }
                else -> LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    item {
                        Text("${objects.size} object${if (objects.size != 1) "s" else ""} extracted",
                            style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                    }
                    items(objects, key = { it.path }) { obj ->
                        PcapCard {
                            Row(
                                Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text(obj.name, style = MaterialTheme.typography.bodyMedium,
                                        color = WarmFgPrimary, maxLines = 2)
                                    Text(formatSize(obj.sizeBytes), style = MaterialTheme.typography.labelSmall,
                                        color = WarmFgMuted)
                                }
                                IconButton(onClick = { shareFile(context, obj.path) }) {
                                    Icon(Icons.Default.Share, "Share", tint = AcOrange400)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}


private fun formatSize(bytes: Long): String {
    if (bytes < 1024) return "${bytes}B"
    var v = bytes.toDouble(); val u = listOf("KB", "MB", "GB"); var i = -1
    while (v >= 1024 && i < u.lastIndex) { v /= 1024; i++ }
    return "%.1f%s".format(v, u[i])
}

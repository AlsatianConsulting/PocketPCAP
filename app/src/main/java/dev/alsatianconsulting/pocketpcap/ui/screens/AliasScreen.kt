package dev.alsatianconsulting.pocketpcap.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.data.EndpointAliasEntity
import dev.alsatianconsulting.pocketpcap.ui.components.AliasDialog
import dev.alsatianconsulting.pocketpcap.ui.components.Eyebrow
import dev.alsatianconsulting.pocketpcap.ui.components.SubtleDivider
import dev.alsatianconsulting.pocketpcap.ui.theme.*

/** Manage user-assigned endpoint aliases: view, edit and remove (spec §3.D). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AliasScreen(
    aliases: List<EndpointAliasEntity>,
    onSetAlias: (String, String) -> Unit,
    onRemoveAlias: (String) -> Unit,
    onBack: () -> Unit,
) {
    var editing by remember { mutableStateOf<EndpointAliasEntity?>(null) }
    var addNew by remember { mutableStateOf(false) }

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
                        Eyebrow("Name resolution")
                        Text("Endpoint aliases", style = MaterialTheme.typography.headlineMedium,
                            color = WarmFgPrimary)
                    }
                },
                actions = {
                    IconButton(onClick = { addNew = true }) {
                        Icon(Icons.Default.Add, "Add alias", tint = AcOrange500)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        }
    ) { padding ->
        if (aliases.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text("No aliases yet.\nTap an endpoint anywhere, or + above, to add one.",
                    style = MaterialTheme.typography.bodyMedium, color = WarmFgMuted,
                    modifier = Modifier.padding(24.dp))
            }
        } else {
            LazyColumn(Modifier.fillMaxSize().padding(padding)) {
                items(aliases, key = { it.address }) { a ->
                    Row(
                        Modifier.fillMaxWidth().clickable { editing = a }
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(a.name, style = MaterialTheme.typography.bodyLarge, color = WarmFgPrimary)
                            Text(a.address, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                color = WarmFgMuted)
                        }
                        IconButton(onClick = { onRemoveAlias(a.address) }) {
                            Icon(Icons.Default.Delete, "Remove", tint = SemanticError)
                        }
                    }
                    SubtleDivider()
                }
            }
        }
    }

    editing?.let { a ->
        AliasDialog(
            address = a.address,
            current = a.name,
            onConfirm = { name -> onSetAlias(a.address, name); editing = null },
            onDismiss = { editing = null },
        )
    }
    if (addNew) {
        NewAliasDialog(
            onConfirm = { addr, name -> if (addr.isNotBlank()) onSetAlias(addr, name); addNew = false },
            onDismiss = { addNew = false },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NewAliasDialog(onConfirm: (String, String) -> Unit, onDismiss: () -> Unit) {
    var addr by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = WarmBg850,
        title = { Text("New alias", color = WarmFgPrimary) },
        text = {
            Column {
                OutlinedTextField(
                    value = addr, onValueChange = { addr = it },
                    placeholder = { Text("192.168.1.1 or AA:BB:CC:DD:EE:FF", color = WarmFgDisabled) },
                    singleLine = true,
                    colors = dialogFieldColors(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = name, onValueChange = { name = it },
                    placeholder = { Text("Name (e.g. Home Router)", color = WarmFgDisabled) },
                    singleLine = true,
                    colors = dialogFieldColors(),
                )
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(addr.trim(), name) }) { Text("Add", color = AcOrange500) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel", color = WarmFgMuted) } },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun dialogFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = AcOrange500, unfocusedBorderColor = BorderSubtle,
    cursorColor = AcOrange500, focusedTextColor = WarmFgPrimary, unfocusedTextColor = WarmFgPrimary,
)

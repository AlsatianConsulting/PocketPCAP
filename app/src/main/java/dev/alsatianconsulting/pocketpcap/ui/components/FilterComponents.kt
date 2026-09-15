package dev.alsatianconsulting.pocketpcap.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.data.SavedFilterEntity
import dev.alsatianconsulting.pocketpcap.filter.FilterBuilders
import dev.alsatianconsulting.pocketpcap.filter.FilterSuggestion
import dev.alsatianconsulting.pocketpcap.filter.SuggestionKind
import dev.alsatianconsulting.pocketpcap.ui.theme.*

/**
 * Wireshark-style filter bar: search icon, live autocomplete dropdown, clear button
 * and a recent/saved-filters menu. Suggestions are supplied by the ViewModel and
 * update as the user types; selection is touch-driven and the hardware/IME action
 * key submits.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FilterBar(
    filterText: String,
    filterError: String?,
    suggestions: List<FilterSuggestion>,
    recentFilters: List<String>,
    savedFilters: List<SavedFilterEntity>,
    onFilterChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onPickSuggestion: (FilterSuggestion) -> Unit,
    onApplyFilter: (String) -> Unit,
    onSaveCurrent: (String) -> Unit,
    onDeleteSaved: (Long) -> Unit,
    onClearRecents: () -> Unit,
) {
    val keyboard = LocalSoftwareKeyboardController.current
    var focused by remember { mutableStateOf(false) }
    var historyOpen by remember { mutableStateOf(false) }
    var saveDialog by remember { mutableStateOf(false) }

    Column {
        OutlinedTextField(
            value = filterText,
            onValueChange = onFilterChange,
            placeholder = {
                Text("Display filter… ip.addr==1.1.1.1, tcp.port==443, http",
                    style = MaterialTheme.typography.bodyMedium, color = WarmFgDisabled)
            },
            textStyle = MaterialTheme.typography.bodyMedium.copy(
                color = WarmFgPrimary, fontFamily = FontFamily.Monospace,
            ),
            leadingIcon = { Icon(Icons.Default.Search, null, tint = WarmFgMuted) },
            trailingIcon = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (filterText.isNotEmpty()) {
                        IconButton(onClick = { onSaveCurrent.let { saveDialog = true } }) {
                            Icon(Icons.Default.BookmarkAdd, "Save filter", tint = WarmFgMuted)
                        }
                        IconButton(onClick = { onFilterChange(""); onSubmit() }) {
                            Icon(Icons.Default.Close, "Clear", tint = WarmFgMuted)
                        }
                    }
                    Box {
                        IconButton(onClick = { historyOpen = true }) {
                            Icon(Icons.Default.History, "Recent filters", tint = AcOrange500)
                        }
                        RecentSavedMenu(
                            expanded = historyOpen,
                            onDismiss = { historyOpen = false },
                            recentFilters = recentFilters,
                            savedFilters = savedFilters,
                            onApplyFilter = { historyOpen = false; onApplyFilter(it) },
                            onDeleteSaved = onDeleteSaved,
                            onClearRecents = { historyOpen = false; onClearRecents() },
                        )
                    }
                }
            },
            isError = filterError != null,
            singleLine = true,
            shape = RoundedCornerShape(0.dp),
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
            keyboardActions = KeyboardActions(onSearch = { keyboard?.hide(); focused = false; onSubmit() }),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = AcOrange500,
                unfocusedBorderColor = BorderSubtle,
                cursorColor = AcOrange500,
                focusedContainerColor = WarmBg850,
                unfocusedContainerColor = WarmBg850,
                errorBorderColor = SemanticError,
            ),
            modifier = Modifier.fillMaxWidth().onFocusChanged { focused = it.isFocused },
        )

        if (filterError != null) {
            Text(filterError,
                style = MaterialTheme.typography.labelSmall, color = SemanticError,
                modifier = Modifier.fillMaxWidth().background(WarmBg850)
                    .padding(horizontal = 16.dp, vertical = 4.dp))
        }

        // Live autocomplete dropdown — shown while the field is focused.
        if (focused && suggestions.isNotEmpty()) {
            LazyColumn(
                Modifier.fillMaxWidth().heightIn(max = 260.dp).background(WarmBg800),
            ) {
                items(suggestions, key = { it.kind.name + "|" + it.apply }) { s ->
                    SuggestionRow(s) { onPickSuggestion(s) }
                    SubtleDivider()
                }
            }
        }
    }

    if (saveDialog) {
        SaveFilterDialog(
            filter = filterText,
            onConfirm = { name -> onSaveCurrent(name); saveDialog = false },
            onDismiss = { saveDialog = false },
        )
    }
}

@Composable
private fun SuggestionRow(s: FilterSuggestion, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier.background(kindColor(s.kind).copy(alpha = 0.15f), RoundedCornerShape(3.dp))
                .padding(horizontal = 5.dp, vertical = 1.dp)
        ) {
            Text(kindTag(s.kind), style = MaterialTheme.typography.labelSmall, color = kindColor(s.kind))
        }
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(s.display, style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                color = WarmFgPrimary, maxLines = 1)
            if (s.detail.isNotBlank()) {
                Text(s.detail, style = MaterialTheme.typography.labelSmall, color = WarmFgMuted, maxLines = 1)
            }
        }
    }
}

@Composable
private fun RecentSavedMenu(
    expanded: Boolean,
    onDismiss: () -> Unit,
    recentFilters: List<String>,
    savedFilters: List<SavedFilterEntity>,
    onApplyFilter: (String) -> Unit,
    onDeleteSaved: (Long) -> Unit,
    onClearRecents: () -> Unit,
) {
    DropdownMenu(expanded = expanded, onDismissRequest = onDismiss, containerColor = WarmBg800) {
        if (savedFilters.isNotEmpty()) {
            Text("Saved", style = MaterialTheme.typography.labelSmall, color = AcOrange400,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp))
            savedFilters.forEach { sf ->
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(sf.name, color = WarmFgPrimary, style = MaterialTheme.typography.bodyMedium)
                            Text(sf.filter, color = WarmFgMuted,
                                style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                                maxLines = 1)
                        }
                    },
                    trailingIcon = {
                        Icon(Icons.Default.Delete, "Delete", tint = WarmFgMuted,
                            modifier = Modifier.clickable { onDeleteSaved(sf.id) })
                    },
                    onClick = { onApplyFilter(sf.filter) },
                )
            }
            SubtleDivider()
        }
        Text("Recent", style = MaterialTheme.typography.labelSmall, color = AcOrange400,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp))
        if (recentFilters.isEmpty()) {
            DropdownMenuItem(
                text = { Text("No recent filters", color = WarmFgMuted) },
                onClick = onDismiss, enabled = false,
            )
        } else {
            recentFilters.forEach { f ->
                DropdownMenuItem(
                    text = {
                        Text(f, color = WarmFgPrimary,
                            style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                            maxLines = 1)
                    },
                    onClick = { onApplyFilter(f) },
                )
            }
            SubtleDivider()
            DropdownMenuItem(
                text = { Text("Clear recent", color = SemanticError) },
                onClick = onClearRecents,
            )
        }
    }
}

@Composable
private fun SaveFilterDialog(filter: String, onConfirm: (String) -> Unit, onDismiss: () -> Unit) {
    var name by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = WarmBg850,
        title = { Text("Save filter", color = WarmFgPrimary) },
        text = {
            Column {
                Text(filter, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = WarmFgMuted)
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = name, onValueChange = { name = it },
                    placeholder = { Text("Name (optional)", color = WarmFgDisabled) },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = AcOrange500, unfocusedBorderColor = BorderSubtle,
                        cursorColor = AcOrange500, focusedTextColor = WarmFgPrimary,
                        unfocusedTextColor = WarmFgPrimary,
                    ),
                )
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(name) }) { Text("Save", color = AcOrange500) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel", color = WarmFgMuted) } },
    )
}

/**
 * Bottom sheet of endpoint filter actions (spec §2) plus alias management.
 * [peer] enables the "conversation" action when both ends are known.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EndpointActionSheet(
    address: String,
    resolvedName: String?,
    existingAlias: String?,
    peer: String? = null,
    onApplyFilter: (String) -> Unit,
    onSetAlias: (String, String) -> Unit,
    onRemoveAlias: (String) -> Unit,
    onLookupLocation: (String) -> Unit = {},
    onDismiss: () -> Unit,
) {
    val isIp = dev.alsatianconsulting.pocketpcap.resolve.AddressUtil.isIpAddress(address)
    var aliasDialog by remember { mutableStateOf(false) }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = WarmBg850) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)) {
            Eyebrow("Endpoint")
            Text(address, style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace),
                color = WarmFgPrimary)
            if (!resolvedName.isNullOrBlank()) {
                Text(resolvedName, style = MaterialTheme.typography.bodySmall, color = AcOrange400)
            }
            Spacer(Modifier.height(8.dp))
            SheetItem("Show all traffic") {
                onApplyFilter(FilterBuilders.endpointFilter(address, FilterBuilders.EndpointAction.ALL)); onDismiss()
            }
            SheetItem("Show source traffic") {
                onApplyFilter(FilterBuilders.endpointFilter(address, FilterBuilders.EndpointAction.SOURCE)); onDismiss()
            }
            SheetItem("Show destination traffic") {
                onApplyFilter(FilterBuilders.endpointFilter(address, FilterBuilders.EndpointAction.DESTINATION)); onDismiss()
            }
            if (!peer.isNullOrBlank()) {
                SheetItem("Show conversation with $peer") {
                    onApplyFilter(FilterBuilders.endpointFilter(address, FilterBuilders.EndpointAction.CONVERSATION, peer)); onDismiss()
                }
            }
            SheetItem("Show sessions (TCP/UDP)") {
                onApplyFilter(FilterBuilders.endpointFilter(address, FilterBuilders.EndpointAction.SESSIONS)); onDismiss()
            }
            if (isIp) {
                SubtleDivider(Modifier.padding(vertical = 4.dp))
                SheetItem("Look up location & WHOIS") {
                    onLookupLocation(address); onDismiss()
                }
            }
            SubtleDivider(Modifier.padding(vertical = 4.dp))
            SheetItem(if (existingAlias != null) "Edit alias ($existingAlias)" else "Set alias…") {
                aliasDialog = true
            }
            if (existingAlias != null) {
                SheetItem("Remove alias", color = SemanticError) { onRemoveAlias(address); onDismiss() }
            }
            Spacer(Modifier.height(12.dp))
        }
    }
    if (aliasDialog) {
        AliasDialog(
            address = address,
            current = existingAlias ?: "",
            onConfirm = { name -> onSetAlias(address, name); aliasDialog = false; onDismiss() },
            onDismiss = { aliasDialog = false },
        )
    }
}

@Composable
fun AliasDialog(address: String, current: String, onConfirm: (String) -> Unit, onDismiss: () -> Unit) {
    var name by remember { mutableStateOf(current) }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = WarmBg850,
        title = { Text("Endpoint alias", color = WarmFgPrimary) },
        text = {
            Column {
                Text(address, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = WarmFgMuted)
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = name, onValueChange = { name = it },
                    placeholder = { Text("e.g. Home Router", color = WarmFgDisabled) },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = AcOrange500, unfocusedBorderColor = BorderSubtle,
                        cursorColor = AcOrange500, focusedTextColor = WarmFgPrimary,
                        unfocusedTextColor = WarmFgPrimary,
                    ),
                )
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(name) }) { Text("Save", color = AcOrange500) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel", color = WarmFgMuted) } },
    )
}

@Composable
private fun SheetItem(label: String, color: androidx.compose.ui.graphics.Color = WarmFgPrimary, onClick: () -> Unit) {
    Text(label, style = MaterialTheme.typography.bodyLarge, color = color,
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 12.dp))
}

private fun kindTag(kind: SuggestionKind): String = when (kind) {
    SuggestionKind.PROTOCOL -> "proto"
    SuggestionKind.FIELD -> "field"
    SuggestionKind.ENDPOINT -> "addr"
    SuggestionKind.HOSTNAME -> "host"
    SuggestionKind.ALIAS -> "alias"
    SuggestionKind.STREAM -> "stream"
    SuggestionKind.RECENT -> "recent"
    SuggestionKind.SAVED -> "saved"
}

private fun kindColor(kind: SuggestionKind) = when (kind) {
    SuggestionKind.PROTOCOL -> AcOrange400
    SuggestionKind.FIELD -> WarmFgMuted
    SuggestionKind.ENDPOINT -> SemanticSuccess
    SuggestionKind.HOSTNAME -> SemanticSuccess
    SuggestionKind.ALIAS -> AcOrange500
    SuggestionKind.STREAM -> SemanticWarning
    SuggestionKind.RECENT -> WarmFgMuted
    SuggestionKind.SAVED -> AcOrange500
}

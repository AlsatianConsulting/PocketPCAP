package dev.alsatianconsulting.pocketpcap.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.alsatianconsulting.pocketpcap.ui.components.Eyebrow
import dev.alsatianconsulting.pocketpcap.ui.theme.*

private enum class LicensePage(val label: String, val asset: String) {
    LICENSE("PocketPCAP", "licenses/LICENSE"),
    NOTICES("Third-party", "licenses/THIRD-PARTY-NOTICES.md"),
}

/**
 * Shows the GPL-3 text and the third-party notices from assets.
 *
 * GPL-3 section 1 requires the licence to travel with the program, and the
 * bundled Wireshark and tun2socks binaries carry their own notice obligations,
 * so both documents ship inside the APK rather than being linked to on the web.
 * `app/build.gradle.kts` copies them from the repository root at build time, so
 * what is displayed here is the same text the repository carries.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LicensesScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var page by remember { mutableStateOf(LicensePage.LICENSE) }
    val scroll = rememberScrollState()

    val text by remember(page) {
        mutableStateOf(
            runCatching {
                context.assets.open(page.asset).bufferedReader().use { it.readText() }
            }.getOrElse { "Licence text unavailable in this build." }
        )
    }

    // A new document starts at the top rather than inheriting the last scroll.
    LaunchedEffect(page) { scroll.scrollTo(0) }

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
                        Eyebrow("Legal")
                        Text("Licences", style = MaterialTheme.typography.headlineMedium,
                            color = WarmFgPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Row(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                LicensePage.entries.forEach { candidate ->
                    val selected = candidate == page
                    Box(
                        modifier = Modifier
                            .background(
                                if (selected) AcOrange500.copy(alpha = 0.15f) else Color.Transparent,
                                RoundedCornerShape(6.dp),
                            )
                            .border(
                                1.dp,
                                if (selected) AcOrange500 else BorderSubtle,
                                RoundedCornerShape(6.dp),
                            )
                            .clickable { page = candidate }
                            .padding(horizontal = 12.dp, vertical = 6.dp),
                    ) {
                        Text(
                            candidate.label,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (selected) AcOrange500 else WarmFgPrimary,
                        )
                    }
                }
            }
            SelectionContainer {
                Text(
                    text,
                    // Monospace at a small size: the GPL is hard-wrapped to 70-odd
                    // columns and only lines up in a fixed-width face.
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        lineHeight = 14.sp,
                    ),
                    color = WarmFgMuted,
                    // Both documents are already hard-wrapped, the GPL to about
                    // seventy columns and the notices into Markdown tables. Letting
                    // Compose re-wrap them on top of that produces ragged, harder to
                    // read text and breaks the tables, so keep the authored line
                    // breaks and pan sideways for anything that overflows.
                    softWrap = false,
                    modifier = Modifier
                        .verticalScroll(scroll)
                        .horizontalScroll(rememberScrollState())
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
        }
    }
}

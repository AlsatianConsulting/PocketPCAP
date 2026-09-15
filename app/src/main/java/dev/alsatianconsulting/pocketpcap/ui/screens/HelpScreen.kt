package dev.alsatianconsulting.pocketpcap.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.ui.components.*
import dev.alsatianconsulting.pocketpcap.ui.theme.*

private data class HelpEntry(val term: String, val body: String)
private data class HelpSection(val title: String, val intro: String, val entries: List<HelpEntry>)

/**
 * In-app reference ("wiki") covering every screen, setting, button and menu. The
 * authoritative long-form version lives in WIKI.md at the repo root; this mirrors
 * its key points so users have the manual on-device.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HelpScreen(onBack: () -> Unit) {
    BackHandler(enabled = true) { onBack() }
    Scaffold(
        containerColor = WarmBg900,
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.Default.ArrowBack, "Back", tint = AcOrange500) }
                },
                title = {
                    Column {
                        Eyebrow("Manual")
                        Text("Help & Wiki", style = MaterialTheme.typography.headlineMedium, color = WarmFgPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        }
    ) { padding ->
        LazyColumn(
            Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            items(SECTIONS) { section ->
                PcapCard {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Eyebrow(section.title)
                        if (section.intro.isNotBlank()) {
                            Text(section.intro, style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                        }
                        section.entries.forEach { e ->
                            Column {
                                Text(e.term, style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                                    color = WarmFgPrimary)
                                Text(e.body, style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
                            }
                        }
                    }
                }
            }
            item { Spacer(Modifier.height(8.dp)) }
        }
    }
}

private val SECTIONS = listOf(
    HelpSection("Sources tab", "Inventory of what the device can capture.", listOf(
        HelpEntry("Root status banner", "Shows whether Magisk root was granted. Only live capture from a network interface needs it; opening, decoding and analysing captures do not."),
        HelpEntry("Network interfaces", "Every link discovered via root `ip` (wlan0, rmnet…), its IPv4 and up/down state."),
        HelpEntry("Capability cards", "Standard and Root groups listing what each capture mode supports on this device."),
        HelpEntry("Diagnostic sources", "Buttons to collect a Bluetooth HCI snoop log, snapshot RIL/modem logs, and enable HCI snoop logging."),
        HelpEntry("Refresh (↻)", "Re-probe root, interfaces and capabilities."),
    )),
    HelpSection("Capture tab", "Start and control live packet capture.", listOf(
        HelpEntry("Source interface chips", "Tap to select. Tap more than one to capture several interfaces simultaneously into one file."),
        HelpEntry("Capture filter", "A BPF capture filter (e.g. `tcp port 443`) applied at the kernel — limits what is recorded."),
        HelpEntry("Start / Pause / Resume / Stop", "Control the running capture. Stop finalizes the pcapng; Pause freezes the capture processes."),
        HelpEntry("Stop", "Stops capture and finalizes the pcapng file. Active foreground captures keep running if the UI is backgrounded."),
        HelpEntry("Output", "Shows the pcapng path being written and bytes captured so far."),
    )),
    HelpSection("Packets tab", "The live/loaded packet list and its tools.", listOf(
        HelpEntry("Display filter", "Full Wireshark display-filter syntax via tshark -Y (e.g. `http`, `ip.addr==1.1.1.1`). Press search to apply."),
        HelpEntry("Autocomplete", "As you type, a dropdown suggests protocols, fields, addresses, hostnames/aliases and stream filters. Tap to insert."),
        HelpEntry("Save / history icons", "Bookmark saves the current filter; the history icon lists recent and saved filters (both persist)."),
        HelpEntry("Tap protocol badge", "Instantly filters to that protocol (DNS→dns, TLSv1.2→tls, HTTP/2→http2…)."),
        HelpEntry("Tap an address", "Opens an endpoint menu: show all/source/destination/conversation/sessions traffic, and set/edit/remove an alias."),
        HelpEntry("Packet row", "Tap to open the decode. Long-press for Follow Stream and protocol filter."),
        HelpEntry("Overflow menu (⋮)", "Analysis (protocol hierarchy + endpoints), Export filtered, Export objects."),
        HelpEntry("Viewing <file> banner", "Appears when a saved file is open; Close returns to the live capture."),
    )),
    HelpSection("Packet detail", "Decode of a single packet.", listOf(
        HelpEntry("Decode tab", "Wireshark protocol tree. Tap a field to highlight its bytes. Long-press for Copy field / Copy value / Apply as filter."),
        HelpEntry("Raw tab", "Hex + ASCII dump; selecting a decode field highlights its bytes here."),
        HelpEntry("Bluetooth notes", "Bluetooth/BLE layers show a plain-language explanation of what each section means."),
    )),
    HelpSection("Analysis (Statistics)", "Capture-wide summaries.", listOf(
        HelpEntry("Protocol hierarchy", "Tree of protocols with packet/byte counts and % of traffic (tshark -z io,phs)."),
        HelpEntry("Endpoints", "Per-address traffic totals with tx/rx split; switch between IPv4/IPv6/TCP/UDP/Eth. Tap a row for the endpoint filter menu; tap a protocol to filter."),
    )),
    HelpSection("Filtering & names", "Interactive filtering and endpoint name resolution.", listOf(
        HelpEntry("Click-to-filter", "Tapping any protocol or endpoint applies the matching display filter and refreshes every view."),
        HelpEntry("Name resolution", "Addresses resolve via your aliases, local discovery (mDNS / NetBIOS / LLMNR), reverse DNS, then MAC vendor (full IEEE OUI). Enable in Settings → Resolve hostnames; NetBIOS/LLMNR query private LAN hosts only."),
        HelpEntry("Display modes", "Settings → Name resolution: show Address, Name + addr, or Name."),
        HelpEntry("Aliases", "Assign your own names to addresses; manage in Settings → Endpoint aliases. They persist and appear as suggestions."),
        HelpEntry("Recent & saved", "Applied filters are remembered; name and keep ones you reuse. Both persist between launches."),
        HelpEntry("Endpoint location", "Tap an IP endpoint → Look up location & WHOIS for offline/custom GeoIP when imported, online GeoIP fallback, and RDAP registration. Private addresses skip network lookup."),
    )),
    HelpSection("Follow stream", "Reconstructs a conversation.", listOf(
        HelpEntry("Client/Server colours", "Blue = client→server, pink = server→client. Copy-all is in the top bar."),
        HelpEntry("TCP/UDP/TLS/HTTP", "Choose from the packet long-press menu; TLS/HTTP require the relevant decryption keys to read payloads."),
    )),
    HelpSection("Export objects", "File → Export Objects equivalent.", listOf(
        HelpEntry("Protocol buttons", "HTTP/TFTP/SMB/Email/DICOM — extracts transferred files from the capture."),
        HelpEntry("Share", "Each reconstructed object can be shared out via the Android share sheet."),
    )),
    HelpSection("Files tab", "Saved captures and logs.", listOf(
        HelpEntry("Load file (＋)", "Import a .pcap/.pcapng from device storage to view and analyse."),
        HelpEntry("Capture file row", "Tap to open in Packets; share or delete with the row icons."),
        HelpEntry("Diagnostic logs", "RIL/modem snapshots; RIL logs open in a parsed request/response viewer."),
    )),
    HelpSection("Settings tab", "Configuration.", listOf(
        HelpEntry("Capture options", "Resolve hostnames (reverse DNS + mDNS), relative timestamps, auto-scroll, preserve raw logs."),
        HelpEntry("Name resolution", "Endpoint display mode, endpoint aliases, and custom offline GeoIP CSV import."),
        HelpEntry("Capture directory", "Where new captures are written. Choose a folder or reset to app storage."),
        HelpEntry("Decryption", "Import a TLS key log (SSLKEYLOGFILE) and/or set a Wi-Fi WPA passphrase to decrypt traffic."),
        HelpEntry("Help & Wiki", "This manual."),
    )),
)

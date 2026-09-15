package dev.alsatianconsulting.pocketpcap.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.resolve.EndpointLocation
import dev.alsatianconsulting.pocketpcap.ui.components.*
import dev.alsatianconsulting.pocketpcap.ui.theme.*

/** GeoIP + WHOIS/RDAP details for a remote endpoint (spec: endpoint locations). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EndpointLocationScreen(
    location: EndpointLocation?,
    loading: Boolean,
    onBack: () -> Unit,
) {
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
                        Eyebrow("Endpoint location")
                        Text(location?.address ?: "Lookup",
                            style = MaterialTheme.typography.titleLarge.copy(fontFamily = FontFamily.Monospace),
                            color = WarmFgPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = WarmBg900),
            )
        }
    ) { padding ->
        when {
            loading -> Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(color = AcOrange500)
                    Spacer(Modifier.height(12.dp))
                    Text("Querying GeoIP + WHOIS…", color = WarmFgMuted,
                        style = MaterialTheme.typography.bodySmall)
                }
            }
            location == null -> Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text("No endpoint selected.", color = WarmFgMuted)
            }
            location.isPrivate -> InfoCenter(padding,
                "Private / local address", "${location.address} is on a local network — no public location or registration.")
            location.error != null && !location.hasAny -> InfoCenter(padding,
                "Lookup unavailable", location.error!!)
            else -> Column(
                Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState())
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                if (location.hasGeo) {
                    LocationCard("Location") {
                        val place = listOfNotNull(location.city, location.region, location.country)
                            .joinToString(", ").ifBlank { null }
                        location.flagEmoji?.let { InfoRow("Flag", it) }
                        place?.let { InfoRow("Place", it) }
                        location.countryCode?.let { InfoRow("Country code", it) }
                        location.postal?.let { InfoRow("Postal", it) }
                        if (location.latitude != null && location.longitude != null)
                            InfoRow("Coordinates", "%.4f, %.4f".format(location.latitude, location.longitude))
                        location.timezone?.let { InfoRow("Timezone", it) }
                        location.geoSource?.let { InfoRow("Source", it) }
                    }
                }
                if (location.asn != null || location.org != null || location.isp != null) {
                    LocationCard("Network") {
                        location.asn?.let { InfoRow("ASN", it) }
                        location.org?.let { InfoRow("Organisation", it) }
                        location.isp?.let { InfoRow("ISP", it) }
                    }
                }
                if (location.hasWhois) {
                    LocationCard("Registration (WHOIS / RDAP)") {
                        location.netName?.let { InfoRow("Network", it) }
                        location.cidr?.let { InfoRow("Range", it) }
                        location.registrant?.let { InfoRow("Registrant", it) }
                        (location.rdapCountry ?: location.countryCode)?.let { InfoRow("Country", it) }
                        location.rir?.let { InfoRow("Registry", it) }
                        location.abuseEmail?.let { InfoRow("Abuse contact", it) }
                    }
                }
                if (!location.hasAny) {
                    Text(location.error ?: "No details found for this endpoint.",
                        color = WarmFgMuted, style = MaterialTheme.typography.bodyMedium)
                }
                Text(
                    if (location.geoSource?.startsWith("Offline") == true)
                        "GeoIP came from the imported offline database. WHOIS/RDAP registration, when shown, is looked up online through rdap.org."
                    else "Looked up online via ipwho.is (GeoIP) and rdap.org (WHOIS). The endpoint address was sent to those services.",
                    style = MaterialTheme.typography.labelSmall, color = WarmFgDisabled)
            }
        }
    }
}

@Composable
private fun InfoCenter(padding: PaddingValues, title: String, body: String) {
    Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(24.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, color = WarmFgPrimary)
            Spacer(Modifier.height(8.dp))
            Text(body, style = MaterialTheme.typography.bodyMedium, color = WarmFgMuted)
        }
    }
}

@Composable
private fun LocationCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    PcapCard {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Eyebrow(title)
            content()
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = WarmFgMuted,
            modifier = Modifier.width(120.dp))
        Text(value, style = MaterialTheme.typography.bodyMedium, color = WarmFgPrimary,
            modifier = Modifier.weight(1f))
    }
}

package dev.alsatianconsulting.pocketpcap.filter

import dev.alsatianconsulting.pocketpcap.resolve.AddressUtil

/** One entry in the autocomplete dropdown. */
data class FilterSuggestion(
    val display: String,    // what the user reads in the dropdown
    val apply: String,      // the full filter text placed in the bar when chosen
    val kind: SuggestionKind,
    val detail: String = "",
)

/** Dynamic context (from the current capture / DB) layered on top of [FilterFields]. */
data class SuggestionContext(
    val endpoints: List<String> = emptyList(),          // raw addresses seen in capture
    val names: List<Pair<String, String>> = emptyList(), // (name, address) aliases + rDNS + mDNS
    val aliases: Set<String> = emptySet(),               // names that are user aliases (for kind)
    val tcpStreams: List<Int> = emptyList(),
    val udpStreams: List<Int> = emptyList(),
    val recentFilters: List<String> = emptyList(),
    val savedFilters: List<Pair<String, String>> = emptyList(), // (name, filter)
)

/**
 * Wireshark-style autocomplete. Completes the trailing token of the query against the
 * static field catalog plus dynamic endpoints/hostnames/streams, and offers recent and
 * saved filters when the bar is empty. Pure and synchronous — safe to unit test and to
 * call on a background thread before posting to the UI.
 */
class FilterSuggestionEngine {

    fun suggest(query: String, ctx: SuggestionContext, max: Int = 12): List<FilterSuggestion> {
        val (prefix, fragment) = splitFragment(query)
        val frag = fragment.trim()
        val out = LinkedHashMap<String, FilterSuggestion>()  // dedupe by apply text

        fun add(s: FilterSuggestion) { if (!out.containsKey(s.apply)) out[s.apply] = s }

        if (frag.isEmpty()) {
            // Empty bar (or trailing operator): surface saved then recent filters.
            ctx.savedFilters.forEach { (name, f) ->
                add(FilterSuggestion(name, f, SuggestionKind.SAVED, f))
            }
            ctx.recentFilters.forEach { f ->
                add(FilterSuggestion(f, f, SuggestionKind.RECENT))
            }
            return out.values.take(max)
        }

        val lower = frag.lowercase()

        // 1. Protocol + field token completions (startsWith ranks above contains).
        val starts = ArrayList<FilterSuggestion>()
        val contains = ArrayList<FilterSuggestion>()
        for (f in FilterFields.all) {
            val t = f.token
            when {
                t.startsWith(lower) -> starts += FilterSuggestion(t, prefix + t, f.kind, f.detail)
                t.contains(lower) -> contains += FilterSuggestion(t, prefix + t, f.kind, f.detail)
            }
        }
        starts.forEach(::add)

        // 2. Endpoint address completion (when fragment looks address-ish).
        if (looksLikeAddressFragment(frag)) {
            for (addr in ctx.endpoints) {
                if (addr.startsWith(frag, ignoreCase = true)) {
                    val apply = if (prefix.isNotBlank()) prefix + addr
                                else "${AddressUtil.addrField(addr)} == $addr"
                    val name = ctx.names.firstOrNull { it.second.equals(addr, true) }?.first
                    add(FilterSuggestion(addr, apply, SuggestionKind.ENDPOINT, name ?: ""))
                }
            }
        }

        // 3. Hostname / alias completion → resolves to an address filter.
        for ((name, addr) in ctx.names) {
            if (name.contains(frag, ignoreCase = true)) {
                val apply = "${AddressUtil.addrField(addr)} == $addr"
                val kind = if (name in ctx.aliases) SuggestionKind.ALIAS else SuggestionKind.HOSTNAME
                add(FilterSuggestion(name, apply, kind, addr))
            }
        }

        // 4. Stream completions ("TCP Stream 5" → tcp.stream eq 5).
        if ("tcp".startsWith(lower) || lower.startsWith("tcp")) {
            ctx.tcpStreams.sorted().forEach { s ->
                add(FilterSuggestion("TCP stream $s", "tcp.stream eq $s", SuggestionKind.STREAM))
            }
        }
        if ("udp".startsWith(lower) || lower.startsWith("udp")) {
            ctx.udpStreams.sorted().forEach { s ->
                add(FilterSuggestion("UDP stream $s", "udp.stream eq $s", SuggestionKind.STREAM))
            }
        }

        // 5. Fall back to contains-matches on fields if we still have room.
        contains.forEach(::add)

        return out.values.take(max)
    }

    companion object {
        /**
         * Split a query into the part to keep ([prefix]) and the trailing token being
         * typed ([fragment]). Boundaries are whitespace and parentheses, so
         * "ip.addr == 192." → prefix="ip.addr == ", fragment="192.".
         */
        fun splitFragment(query: String): Pair<String, String> {
            if (query.isEmpty()) return "" to ""
            var i = query.length
            while (i > 0) {
                val c = query[i - 1]
                if (c == ' ' || c == '\t' || c == '(' || c == ')') break
                i--
            }
            return query.substring(0, i) to query.substring(i)
        }

        private fun looksLikeAddressFragment(frag: String): Boolean {
            if (frag.isEmpty()) return false
            // Digits, dots, colons, hex — i.e. the start of an IPv4/IPv6/MAC.
            return frag.all { it.isDigit() || it == '.' || it == ':' || it in 'a'..'f' || it in 'A'..'F' } &&
                frag.any { it.isDigit() || it == '.' || it == ':' }
        }
    }
}

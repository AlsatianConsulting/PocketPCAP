package dev.alsatianconsulting.pocketpcap.analysis

import dev.alsatianconsulting.pocketpcap.model.TrafficMapRoute
import dev.alsatianconsulting.pocketpcap.model.TrafficMapState
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AnalysisExportTest {

    private fun analysisWith(vararg conversations: Conversation) = CaptureAnalysis(
        metadata = CaptureMetadata(filename = "capture.pcapng", packetCount = 2, sizeBytes = 128),
        conversations = conversations.toList(),
    )

    private fun conversation(a: String, b: String, filter: String) = Conversation(
        id = "c-$a-$b", kind = ConversationKind.TCP, endpointA = a, endpointB = b,
        portA = 1234, portB = 443, packets = 10, bytes = 2048,
        packetsAToB = 6, bytesAToB = 1024, packetsBToA = 4, bytesBToA = 1024,
        startSeconds = 1.5, durationSeconds = 2.5, streamIndex = 0, filter = filter,
    )

    /**
     * Durations are differences between two capture timestamps, so binary floating
     * point leaves artefacts. A real export of a 0.3 s conversation read
     * "0.3000000000000007", which is noise in a column a person is meant to read.
     */
    @Test
    fun csvRoundsSecondsInsteadOfLeakingFloatingPointArtefacts() {
        val noisy = conversation("10.0.0.1", "1.1.1.1", "tcp.stream == 0")
            .copy(startSeconds = 8.0, durationSeconds = 8.3 - 8.0)
        val csv = AnalysisExport.csv(analysisWith(noisy), AnalysisExport.Table.CONVERSATIONS)
        val cells = csv.trim().lines()[1].split(",")
        assertEquals("8", cells[11])      // startSeconds
        assertEquals("0.3", cells[12])    // durationSeconds
    }

    /** Small durations must stay plain decimal; a spreadsheet reads 3.0E-7 as text. */
    @Test
    fun csvNeverUsesScientificNotationForSmallDurations() {
        val tiny = conversation("10.0.0.1", "1.1.1.1", "tcp.stream == 0")
            .copy(startSeconds = 0.0, durationSeconds = 0.0000003)
        val cells = AnalysisExport.csv(analysisWith(tiny), AnalysisExport.Table.CONVERSATIONS)
            .trim().lines()[1].split(",")
        assertTrue("scientific notation: ${cells[12]}", !cells[12].contains("E", ignoreCase = true))
    }

    @Test
    fun jsonRoundsSecondsToo() {
        val noisy = conversation("10.0.0.1", "1.1.1.1", "tcp.stream == 0")
            .copy(durationSeconds = 8.3 - 8.0)
        val rows = JSONObject(AnalysisExport.json(analysisWith(noisy), AnalysisExport.Table.CONVERSATIONS))
            .getJSONArray("rows")
        assertEquals(0.3, rows.getJSONObject(0).getDouble("durationSeconds"), 0.0)
    }

    @Test
    fun csvHasAHeaderAndOneRowPerRecord() {
        val csv = AnalysisExport.csv(
            analysisWith(conversation("10.0.0.1", "1.1.1.1", "tcp.stream == 0")),
            AnalysisExport.Table.CONVERSATIONS,
        )
        val lines = csv.trim().lines()
        assertEquals(2, lines.size)
        assertTrue(lines[0].startsWith("kind,endpointA,portA,endpointB,portB,packets,bytes"))
        assertTrue(lines[1].startsWith("TCP,10.0.0.1,1234,1.1.1.1,443,10,2048"))
    }

    /**
     * Filters contain commas and quotes routinely. An unquoted one shifts every
     * later column, which is the classic way a CSV export looks fine and is wrong.
     */
    @Test
    fun csvQuotesSeparatorsAndEmbeddedQuotes() {
        val filter = "http.host == " + '"' + "a,b" + '"'
        val csv = AnalysisExport.csv(
            analysisWith(conversation("10.0.0.1", "1.1.1.1", filter)),
            AnalysisExport.Table.CONVERSATIONS,
        )
        val header = parseCsvLine(csv.trim().lines()[0])
        val row = parseCsvLine(csv.trim().lines()[1])
        // The comma inside the filter must not become a field separator.
        assertEquals(header.size, row.size)
        // And the value must survive the round trip exactly.
        assertEquals(filter, row[header.indexOf("filter")])
    }

    @Test
    fun csvOfAnEmptyTableIsEmptyRatherThanAStrayHeader() {
        assertEquals("", AnalysisExport.csv(analysisWith(), AnalysisExport.Table.CONVERSATIONS))
    }

    @Test
    fun jsonCarriesCaptureContextAndRows() {
        val json = JSONObject(
            AnalysisExport.json(
                analysisWith(conversation("10.0.0.1", "1.1.1.1", "tcp")),
                AnalysisExport.Table.CONVERSATIONS,
            )
        )
        assertEquals("capture.pcapng", json.getJSONObject("capture").getString("filename"))
        assertEquals("conversations", json.getString("table"))
        val rows = json.getJSONArray("rows")
        assertEquals(1, rows.length())
        assertEquals("10.0.0.1", rows.getJSONObject(0).getString("endpointA"))
        assertEquals(2048, rows.getJSONObject(0).getInt("bytes"))
    }

    private fun mapState() = TrafficMapState(
        sourceAddress = "203.0.113.1", sourceLabel = "Here",
        sourceLatitude = 51.5, sourceLongitude = -0.1,
        routes = listOf(
            TrafficMapRoute(
                address = "1.1.1.1", label = "one.one.one.one", packets = 5, bytes = 500,
                txPackets = 3, txBytes = 300, rxPackets = 2, rxBytes = 200,
                trafficType = "DNS", city = "Sydney", region = null, country = "AU",
                latitude = -33.9, longitude = 151.2,
            )
        ),
    )

    @Test
    fun geoJsonEmitsAPointAndARouteWithLonLatOrder() {
        val root = JSONObject(AnalysisExport.geoJson(mapState()))
        assertEquals("FeatureCollection", root.getString("type"))
        val features = root.getJSONArray("features")
        assertEquals(2, features.length())   // the endpoint, plus the line from source

        val point = features.getJSONObject(0)
        assertEquals("Point", point.getJSONObject("geometry").getString("type"))
        val coords = point.getJSONObject("geometry").getJSONArray("coordinates")
        // GeoJSON is longitude first; swapping them silently puts pins in the sea.
        assertEquals(151.2, coords.getDouble(0), 1e-9)
        assertEquals(-33.9, coords.getDouble(1), 1e-9)
        assertEquals("1.1.1.1", point.getJSONObject("properties").getString("address"))

        assertEquals("LineString", features.getJSONObject(1).getJSONObject("geometry").getString("type"))
    }

    @Test
    fun kmlIsWellFormedAndEscapesMarkup() {
        val state = mapState().let {
            it.copy(routes = it.routes.map { r -> r.copy(label = "a & b <c>") })
        }
        val kml = AnalysisExport.kml(state, "cap<ture>")
        assertTrue(kml.startsWith("<?xml"))
        assertTrue(kml.trim().endsWith("</kml>"))
        assertTrue("ampersand must be escaped", kml.contains("a &amp; b &lt;c&gt;"))
        assertTrue("title must be escaped", kml.contains("cap&lt;ture&gt;"))
        assertTrue("KML is longitude first", kml.contains("151.2,-33.9,0"))
        // No raw markup leaked from user-controlled text.
        assertTrue(!kml.contains("<c>"))
    }

    /** Split and unquote a CSV line the way a reader would. */
    private fun parseCsvLine(line: String): List<String> {
        val fields = mutableListOf<String>()
        val cell = StringBuilder()
        var inQuotes = false
        var i = 0
        while (i < line.length) {
            val c = line[i]
            when {
                c == '"' && inQuotes && i + 1 < line.length && line[i + 1] == '"' -> {
                    cell.append('"'); i++
                }
                c == '"' -> inQuotes = !inQuotes
                c == ',' && !inQuotes -> { fields += cell.toString(); cell.clear() }
                else -> cell.append(c)
            }
            i++
        }
        fields += cell.toString()
        return fields
    }
}

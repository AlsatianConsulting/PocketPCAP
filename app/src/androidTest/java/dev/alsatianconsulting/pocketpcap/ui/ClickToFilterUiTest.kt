package dev.alsatianconsulting.pocketpcap.ui

import androidx.activity.ComponentActivity
import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.alsatianconsulting.pocketpcap.ui.components.PacketRow
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Touch-interaction tests for protocol + endpoint click-to-filter on a packet row. */
@RunWith(AndroidJUnit4::class)
class ClickToFilterUiTest {

    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun tappingProtocolBadge_firesProtocolClick() {
        var protocolClicked = false
        var srcClicked = false
        rule.setContent {
            MaterialTheme {
                PacketRow(
                    number = 1, time = "0.0", src = "192.168.1.10", dst = "8.8.8.8",
                    protocol = "DNS", length = 80, info = "query",
                    protocolColor = Color.Cyan, isSelected = false,
                    onClick = {},
                    onProtocolClick = { protocolClicked = true },
                    onSrcClick = { srcClicked = true },
                )
            }
        }
        rule.onNodeWithText("DNS").performClick()
        assertEquals(true, protocolClicked)

        rule.onNodeWithText("192.168.1.10").performClick()
        assertEquals(true, srcClicked)
    }
}

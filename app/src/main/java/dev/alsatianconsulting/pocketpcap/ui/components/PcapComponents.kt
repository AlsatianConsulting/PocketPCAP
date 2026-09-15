package dev.alsatianconsulting.pocketpcap.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalViewConfiguration
import androidx.compose.ui.platform.ViewConfiguration
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.TextUnitType
import androidx.compose.ui.unit.dp
import dev.alsatianconsulting.pocketpcap.model.CapState
import dev.alsatianconsulting.pocketpcap.ui.theme.*

@Composable
fun Eyebrow(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text.uppercase(),
        style = MaterialTheme.typography.labelSmall.copy(
            letterSpacing = TextUnit(0.15f, TextUnitType.Em)
        ),
        color = AcOrange400,
        modifier = modifier.padding(bottom = 4.dp),
    )
}

@Composable
fun SubtleDivider(modifier: Modifier = Modifier) {
    HorizontalDivider(modifier = modifier, thickness = 1.dp, color = BorderSubtle)
}

@Composable
fun StateDot(state: CapState, modifier: Modifier = Modifier) {
    val color = when (state) {
        CapState.AVAILABLE     -> SemanticSuccess
        CapState.UNAVAILABLE   -> SemanticError
        CapState.UNKNOWN       -> SemanticWarning
        CapState.REQUIRES_ROOT -> AcOrange500
    }
    Box(modifier = modifier.size(8.dp).background(color, RoundedCornerShape(50)))
}

@Composable
fun CapabilityRow(label: String, detail: String, state: CapState, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        StateDot(state = state, modifier = Modifier.padding(top = 5.dp))
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyLarge, color = WarmFgPrimary)
            Text(detail, style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
        }
    }
}

@Composable
fun InterfaceChip(name: String, isSelected: Boolean, isUp: Boolean, onClick: () -> Unit) {
    val bg = if (isSelected) AcOrange500.copy(alpha = 0.15f) else Color.Transparent
    val borderColor = if (isSelected) AcOrange500 else BorderSubtle

    Box(
        modifier = Modifier
            .background(bg, RoundedCornerShape(6.dp))
            .border(1.dp, borderColor, RoundedCornerShape(6.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(6.dp).background(
                    if (isUp) SemanticSuccess else WarmFgDisabled,
                    RoundedCornerShape(50)
                )
            )
            Spacer(Modifier.width(8.dp))
            Text(
                name,
                style = MaterialTheme.typography.bodyMedium,
                color = if (isSelected) AcOrange500 else WarmFgPrimary,
            )
        }
    }
}

@Composable
fun PcapCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(WarmBg850, RoundedCornerShape(8.dp))
            .border(1.dp, BorderSubtle, RoundedCornerShape(8.dp)),
        content = content,
    )
}

@Composable
fun PrimaryButton(
    text: String,
    icon: ImageVector? = null,
    onClick: () -> Unit,
    enabled: Boolean = true,
    modifier: Modifier = Modifier,
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(6.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = AcOrange500,
            contentColor = WarmBg900,
            disabledContainerColor = WarmBg700,
            disabledContentColor = WarmFgDisabled,
        ),
        modifier = modifier.height(44.dp),
    ) {
        if (icon != null) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
        }
        Text(text, style = MaterialTheme.typography.titleSmall)
    }
}

@Composable
fun DestructiveButton(
    text: String,
    icon: ImageVector? = null,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    OutlinedButton(
        onClick = onClick,
        shape = RoundedCornerShape(6.dp),
        border = BorderStroke(1.dp, SemanticError),
        colors = ButtonDefaults.outlinedButtonColors(contentColor = SemanticError),
        modifier = modifier.height(44.dp),
    ) {
        if (icon != null) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
        }
        Text(text, style = MaterialTheme.typography.titleSmall)
    }
}

@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
fun PacketRow(
    number: Long,
    time: String,
    src: String,
    dst: String,
    protocol: String,
    length: Int,
    info: String,
    protocolColor: Color,
    isSelected: Boolean,
    onClick: () -> Unit,
    onLongClick: (() -> Unit)? = null,
    srcLabel: String = src,
    dstLabel: String = dst,
    onProtocolClick: (() -> Unit)? = null,
    onSrcClick: (() -> Unit)? = null,
    onDstClick: (() -> Unit)? = null,
) {
    val bg = if (isSelected) AcOrange500.copy(alpha = 0.08f) else Color.Transparent
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(bg)
            .combinedClickable(onClick = onClick, onLongClick = onLongClick)
            .padding(horizontal = 12.dp, vertical = 6.dp),
    ) {
        // The protocol badge and the src/dst addresses are click-to-filter targets
        // *inside* a row whose own tap opens the packet detail. Compose hit-testing
        // expands every pointer-input node to LocalViewConfiguration's 48dp minimum,
        // so on this 149px row each address grew to 126px tall, centred on its own
        // 38px line, and covered the number line above and the info line below.
        // Between them they swallowed all but a 42px-wide gap around the arrow, so
        // tapping a packet almost always opened an endpoint filter sheet instead of
        // the decode tree. Hold these inner targets to their drawn bounds; the row
        // itself keeps the default and stays comfortably tappable.
        CompositionLocalProvider(LocalViewConfiguration provides ExactTouchBounds(LocalViewConfiguration.current)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "%5d".format(number),
                style = MaterialTheme.typography.labelSmall,
                color = WarmFgMuted,
                modifier = Modifier.width(40.dp),
            )
            Spacer(Modifier.width(6.dp))
            Box(
                Modifier
                    .background(protocolColor.copy(alpha = 0.15f), RoundedCornerShape(3.dp))
                    .then(if (onProtocolClick != null) Modifier.clickable(onClick = onProtocolClick) else Modifier)
                    .padding(horizontal = 5.dp, vertical = 1.dp)
            ) {
                Text(protocol, style = MaterialTheme.typography.labelSmall, color = protocolColor)
            }
            Spacer(Modifier.weight(1f))
            Text(time, style = MaterialTheme.typography.labelSmall, color = WarmFgMuted)
            Spacer(Modifier.width(8.dp))
            Text("${length}B", style = MaterialTheme.typography.labelSmall, color = WarmFgMuted)
        }
        Spacer(Modifier.height(2.dp))
        Row {
            Text(srcLabel, style = MaterialTheme.typography.bodySmall, color = WarmFgPrimary,
                maxLines = 1,
                modifier = Modifier.weight(1f)
                    .then(if (onSrcClick != null) Modifier.clickable(onClick = onSrcClick) else Modifier))
            Text(" → ", style = MaterialTheme.typography.bodySmall, color = WarmFgMuted)
            Text(dstLabel, style = MaterialTheme.typography.bodySmall, color = WarmFgPrimary,
                maxLines = 1,
                modifier = Modifier.weight(1f)
                    .then(if (onDstClick != null) Modifier.clickable(onClick = onDstClick) else Modifier))
        }
        }
        if (info.isNotEmpty()) {
            Text(info, style = MaterialTheme.typography.bodySmall, color = WarmFgMuted, maxLines = 1)
        }
    }
}

/**
 * A ViewConfiguration that drops the 48dp minimum touch target, so a pointer-input
 * node is hit only within the bounds it actually draws. Used for the secondary
 * click-to-filter targets nested inside a packet row, where the default expansion
 * overlaps and steals the row's own tap.
 */
private class ExactTouchBounds(private val base: ViewConfiguration) : ViewConfiguration by base {
    override val minimumTouchTargetSize: DpSize get() = DpSize.Zero
}

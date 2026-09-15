package dev.alsatianconsulting.pocketpcap.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val PocketPcapColorScheme = darkColorScheme(
    primary              = AcOrange500,
    onPrimary            = WarmBg900,
    primaryContainer     = WarmBg700,
    onPrimaryContainer   = AcOrange300,

    secondary            = AcOrange400,
    onSecondary          = WarmBg900,
    secondaryContainer   = WarmBg800,
    onSecondaryContainer = AcOrange400,

    background           = WarmBg900,
    onBackground         = WarmFgPrimary,

    surface              = WarmBg850,
    onSurface            = WarmFgPrimary,
    surfaceVariant       = WarmBg800,
    onSurfaceVariant     = WarmFgMuted,

    outline              = BorderDefault,
    outlineVariant       = BorderSubtle,

    error                = SemanticError,
    onError              = WarmFgPrimary,
    errorContainer       = Color(0xFF7F1D1D),
    onErrorContainer     = Color(0xFFFCA5A5),
)

@Composable
fun PocketPcapTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = PocketPcapColorScheme,
        typography  = PocketPcapTypography,
        content     = content
    )
}

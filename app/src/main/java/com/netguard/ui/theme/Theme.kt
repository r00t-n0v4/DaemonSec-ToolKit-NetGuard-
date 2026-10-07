package com.netguard.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColors = darkColorScheme(
    primary = SignalYellow,
    onPrimary = NetBlack,
    secondary = TerminalGreen,
    onSecondary = NetBlack,
    tertiary = GlitchMagenta,
    background = NetBlack,
    onBackground = Color(0xFFEDEDED),
    surface = PanelBlack,
    onSurface = Color(0xFFEDEDED),
    surfaceVariant = PanelBlack,
    onSurfaceVariant = Color(0xFFB3B3B3),
    error = AlertRed,
    onError = NetBlack,
    outline = Color(0xFF333333)
)

/** Dark-only by design — this is a black/yellow terminal aesthetic app. */
@Composable
fun NetGuardTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColors,
        typography = AppTypography,
        content = content
    )
}
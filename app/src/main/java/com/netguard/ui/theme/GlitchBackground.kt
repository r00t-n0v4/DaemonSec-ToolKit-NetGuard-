package com.netguard.ui.theme

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import kotlin.random.Random

/**
 * The thin horizontal color streaks from the reference mockup — kept
 * genuinely subtle (low alpha, slow drift, sparse) since this sits behind
 * real UI content. The goal is ambient texture that reads as "glitch" in
 * peripheral vision, not something that competes with the findings feed
 * for attention or makes small text harder to read. Pure Canvas, no
 * assets, cheap enough to run continuously without draining battery.
 */
@Composable
fun GlitchStreakBackground(modifier: Modifier = Modifier) {
    val transition = rememberInfiniteTransition(label = "glitch-drift")
    val drift by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 9000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "drift"
    )

    // Fixed seed so the streak layout is stable across recompositions —
    // only their vertical drift position animates, not their count/color/length.
    val streaks = remember { generateStreaks(count = 14) }

    Canvas(modifier = modifier.fillMaxSize()) {
        streaks.forEach { streak ->
            drawStreak(streak, drift, size.height, size.width)
        }
    }
}

private data class Streak(
    val baseYFraction: Float,   // 0f..1f vertical position
    val xStartFraction: Float,  // 0f..1f where it starts horizontally
    val widthFraction: Float,   // fraction of screen width it spans
    val color: Color,
    val thicknessDp: Float,
    val speedMultiplier: Float, // varies drift speed per streak so they don't move in lockstep
    val alpha: Float
)

private fun generateStreaks(count: Int): List<Streak> {
    val random = Random(42) // deterministic layout, looks designed rather than random-per-launch
    val palette = listOf(SignalYellowGlow, TerminalGreen, GlitchMagenta)
    return List(count) {
        Streak(
            baseYFraction = random.nextFloat(),
            xStartFraction = random.nextFloat() * 0.6f,
            widthFraction = 0.15f + random.nextFloat() * 0.25f,
            color = palette[random.nextInt(palette.size)],
            thicknessDp = 1.5f + random.nextFloat() * 2f,
            speedMultiplier = 0.5f + random.nextFloat(),
            alpha = 0.05f + random.nextFloat() * 0.08f // intentionally faint — ambient, not decorative-foreground
        )
    }
}

private fun DrawScope.drawStreak(streak: Streak, drift: Float, canvasHeight: Float, canvasWidth: Float) {
    // Each streak drifts downward and wraps — modulo keeps it continuous
    // without a visible reset jump.
    val animatedY = ((streak.baseYFraction + drift * streak.speedMultiplier) % 1f) * canvasHeight
    val xStart = streak.xStartFraction * canvasWidth
    val width = streak.widthFraction * canvasWidth

    drawLine(
        color = streak.color.copy(alpha = streak.alpha),
        start = Offset(xStart, animatedY),
        end = Offset((xStart + width).coerceAtMost(canvasWidth), animatedY),
        strokeWidth = streak.thicknessDp
    )
}
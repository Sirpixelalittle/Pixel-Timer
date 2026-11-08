package com.roottimer.app.ui

import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.graphics.Color

val Bg = Color(0xFF0C0E12)
val Surface1 = Color(0xFF14181F)
val Surface2 = Color(0xFF1B212B)
val Accent = Color(0xFF64B5F6)
val AccentDim = Color(0xFF42A5F5)
val OnAccent = Color(0xFF08233C)
val TextPrimary = Color(0xFFE6EDF3)
val TextSecondary = Color(0xFF8B98A5)
val Danger = Color(0xFFF87171)
val Warn = Color(0xFFFBBF24)
val Term = Color(0xFF0A0C10)

val RootTimerColors = darkColorScheme(
    primary = Accent,
    onPrimary = OnAccent,
    primaryContainer = Color(0xFF173752),
    onPrimaryContainer = Accent,
    secondary = AccentDim,
    onSecondary = OnAccent,
    background = Bg,
    onBackground = TextPrimary,
    surface = Surface1,
    onSurface = TextPrimary,
    surfaceVariant = Surface2,
    onSurfaceVariant = TextSecondary,
    outline = Color(0xFF2A313C),
    error = Danger,
    onError = Color(0xFF2A0A0A),
)

package com.nexlock.security.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// NEXLOCK Mandatory Color Palette (Dark Mode Primary)
val NexBackgroundDark = Color(0xFF0B1020)
val NexSurfaceDark = Color(0xFF151D32)
val NexPrimary = Color(0xFF5B8CFF)
val NexSecondary = Color(0xFF9B7BFF)
val NexSuccess = Color(0xFF2DD4A3)
val NexTextPrimaryDark = Color(0xFFF5F7FF)
val NexTextSecondaryDark = Color(0xFFA6B0C3)

// NEXLOCK Light Mode Counterparts
val NexBackgroundLight = Color(0xFFF4F7FB)
val NexSurfaceLight = Color(0xFFFFFFFF)
val NexTextPrimaryLight = Color(0xFF0F172A)
val NexTextSecondaryLight = Color(0xFF475569)

private val DarkColorPalette = darkColorScheme(
    primary = NexPrimary,
    secondary = NexSecondary,
    tertiary = NexSuccess,
    background = NexBackgroundDark,
    surface = NexSurfaceDark,
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = NexTextPrimaryDark,
    onSurface = NexTextPrimaryDark,
    onSurfaceVariant = NexTextSecondaryDark
)

private val LightColorPalette = lightColorScheme(
    primary = NexPrimary,
    secondary = NexSecondary,
    tertiary = NexSuccess,
    background = NexBackgroundLight,
    surface = NexSurfaceLight,
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = NexTextPrimaryLight,
    onSurface = NexTextPrimaryLight,
    onSurfaceVariant = NexTextSecondaryLight
)

val NexTypography = Typography(
    headlineLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 28.sp,
        lineHeight = 34.sp
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 26.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp,
        lineHeight = 22.sp
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp
    )
)

enum class ThemeMode {
    DARK, LIGHT, SYSTEM
}

@Composable
fun NexLockTheme(
    themeMode: ThemeMode = ThemeMode.DARK,
    content: @Composable () -> Unit
) {
    val useDark = when (themeMode) {
        ThemeMode.DARK -> true
        ThemeMode.LIGHT -> false
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
    }

    MaterialTheme(
        colorScheme = if (useDark) DarkColorPalette else LightColorPalette,
        typography = NexTypography,
        content = content
    )
}

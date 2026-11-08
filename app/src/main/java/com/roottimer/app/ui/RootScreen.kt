package com.roottimer.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.RestartAlt
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.roottimer.app.R

/** One app-level status line: dot + label + colored text. */
@Composable
fun StatusRow(label: String, value: String, dotColor: Color) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .size(9.dp)
                .background(dotColor, CircleShape)
        )
        Spacer(Modifier.width(10.dp))
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = TextSecondary
        )
        Spacer(Modifier.width(8.dp))
        Text(
            value,
            style = MaterialTheme.typography.labelLarge,
            color = dotColor,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
fun RootScreen(
    rootLabel: String,
    rootDetail: String,
    rootDot: Color,
    shizukuLabel: String,
    shizukuDot: Color,
    statusText: String,
    statusColor: Color,
    runLabel: String,
    runEnabled: Boolean,
    isRunning: Boolean,
    autoRoot: Boolean,
    logs: List<String>,
    onRun: () -> Unit,
    onAutoToggle: (Boolean) -> Unit,
    onOpenManager: () -> Unit,
) {
    Surface(color = Bg, modifier = Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize()) {
            // ── Header ────────────────────────────────────────────────
            Column(
                Modifier
                    .fillMaxWidth()
                    .padding(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 12.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.Bolt,
                        contentDescription = null,
                        tint = Accent,
                        modifier = Modifier.size(28.dp)
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        stringResource(R.string.app_title),
                        fontSize = 26.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary
                    )
                    Spacer(Modifier.weight(1f))
                    Surface(
                        color = Surface2,
                        shape = RoundedCornerShape(50)
                    ) {
                        Text(
                            "v1.3",
                            Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                            fontSize = 11.sp,
                            color = TextSecondary
                        )
                    }
                }
                Text(
                    stringResource(R.string.app_subtitle),
                    Modifier.padding(top = 2.dp),
                    fontSize = 13.sp,
                    color = TextSecondary
                )
                Text(
                    stringResource(R.string.tested_profile),
                    Modifier.padding(top = 2.dp),
                    fontSize = 12.sp,
                    color = Warn
                )
                Text(
                    stringResource(R.string.credits),
                    Modifier.padding(top = 2.dp),
                    fontSize = 11.sp,
                    color = Accent
                )
            }

            // ── Status card ──────────────────────────────────────────
            Card(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                colors = CardDefaults.cardColors(containerColor = Surface1),
                shape = RoundedCornerShape(18.dp)
            ) {
                Column(Modifier.padding(18.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            if (rootDot == Accent) Icons.Filled.CheckCircle else Icons.Filled.Info,
                            contentDescription = null,
                            tint = rootDot,
                            modifier = Modifier.size(30.dp)
                        )
                        Spacer(Modifier.width(12.dp))
                        Column {
                            Text(
                                rootLabel,
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Bold,
                                color = rootDot
                            )
                            Text(
                                rootDetail,
                                fontSize = 12.sp,
                                color = TextSecondary
                            )
                        }
                    }
                    Spacer(Modifier.height(14.dp))
                    HorizontalDivider(color = Color(0xFF232A34))
                    Spacer(Modifier.height(12.dp))
                    StatusRow("Shizuku", shizukuLabel, shizukuDot)
                    Spacer(Modifier.height(6.dp))
                    TextButton(onClick = onOpenManager) {
                        Text(
                            stringResource(R.string.manager_button),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Accent
                        )
                    }
                }
            }

            Spacer(Modifier.height(14.dp))

            // ── Run button ───────────────────────────────────────────
            Button(
                onClick = onRun,
                enabled = runEnabled,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .height(56.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Accent,
                    contentColor = OnAccent,
                    disabledContainerColor = Surface2,
                    disabledContentColor = TextSecondary
                )
            ) {
                if (isRunning) {
                    CircularProgressIndicator(
                        Modifier.size(22.dp),
                        color = OnAccent,
                        strokeWidth = 2.5.dp
                    )
                    Spacer(Modifier.width(12.dp))
                    Text(runLabel, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                } else {
                    Icon(
                        if (rootDot == Accent) Icons.Filled.RestartAlt else Icons.Filled.Bolt,
                        contentDescription = null,
                        modifier = Modifier.size(22.dp)
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(runLabel, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                }
            }

            Spacer(Modifier.height(10.dp))

            // ── Status line ──────────────────────────────────────────
            if (statusText.isNotBlank()) {
                Text(
                    statusText,
                    Modifier.fillMaxWidth(),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    color = statusColor,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
                Spacer(Modifier.height(6.dp))
            }

            Spacer(Modifier.height(6.dp))

            // ── Auto-root switch ─────────────────────────────────────
            Card(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                colors = CardDefaults.cardColors(containerColor = Surface1),
                shape = RoundedCornerShape(18.dp)
            ) {
                Row(
                    Modifier.padding(horizontal = 18.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            stringResource(R.string.auto_title),
                            fontSize = 15.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = TextPrimary
                        )
                        Text(
                            stringResource(R.string.auto_desc),
                            fontSize = 11.sp,
                            color = TextSecondary
                        )
                    }
                    Switch(
                        checked = autoRoot,
                        onCheckedChange = onAutoToggle,
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = OnAccent,
                            checkedTrackColor = Accent,
                            uncheckedThumbColor = TextSecondary,
                            uncheckedTrackColor = Surface2
                        )
                    )
                }
            }

            Spacer(Modifier.height(14.dp))

            // ── Log terminal ─────────────────────────────────────────
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Filled.Description,
                    contentDescription = null,
                    tint = TextSecondary,
                    modifier = Modifier.size(14.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    stringResource(R.string.log_label),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = TextSecondary,
                    letterSpacing = 2.sp
                )
            }
            Spacer(Modifier.height(6.dp))
            Card(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .weight(1f)
                    .padding(bottom = 16.dp),
                colors = CardDefaults.cardColors(containerColor = Term),
                shape = RoundedCornerShape(16.dp)
            ) {
                val listState = rememberLazyListState()
                LaunchedEffect(logs.size) {
                    if (logs.isNotEmpty()) listState.animateScrollToItem(logs.size - 1)
                }
                LazyColumn(
                    state = listState,
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 14.dp, vertical = 12.dp)
                ) {
                    items(logs) { line ->
                        val color = when {
                            line.contains("ROOT OK") || line.contains("KSU_LOADED") ||
                                line.contains("성공") || line.contains("verified") -> Accent
                            line.contains("실패") || line.contains("error") ||
                                line.contains("[-]") -> Danger
                            line.contains("[!]") || line.contains("warn") -> Warn
                            else -> Color(0xFFB7C2CE)
                        }
                        Text(
                            line,
                            fontSize = 11.sp,
                            lineHeight = 15.sp,
                            fontFamily = FontFamily.Monospace,
                            color = color
                        )
                    }
                }
            }
        }
    }
}

package com.roottimer.app

import android.content.ComponentName
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.ui.res.stringResource
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import com.roottimer.app.ui.Accent
import com.roottimer.app.ui.Danger
import com.roottimer.app.ui.RootScreen
import com.roottimer.app.ui.RootTimerColors
import com.roottimer.app.ui.TextPrimary
import com.roottimer.app.ui.TextSecondary
import com.roottimer.app.ui.Warn
import rikka.shizuku.Shizuku
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

class MainActivity : ComponentActivity() {

    private val main = Handler(Looper.getMainLooper())
    private val running = AtomicBoolean(false)

    // ── Compose state ────────────────────────────────────────────────
    private var rootLabel by mutableStateOf("")
    private var rootDetail by mutableStateOf(" ")
    private var rootDot by mutableStateOf(Color(0xFF8B98A5))
    private var shizukuLabel by mutableStateOf("")
    private var shizukuDot by mutableStateOf(Color(0xFF8B98A5))
    private var runLabel by mutableStateOf("")
    private var runEnabled by mutableStateOf(false)
    private var isRunning by mutableStateOf(false)
    private var statusText by mutableStateOf("")
    private var statusColor by mutableStateOf(Color(0xFF8B98A5))
    private var autoRoot by mutableStateOf(false)
    private var showRunConfirm by mutableStateOf(false)
    private var showAutoConfirm by mutableStateOf(false)
    private var showManagerDialog by mutableStateOf(false)
    private val logs = mutableStateListOf<String>()

    private var boundService: IRootService? = null
    private var boundArgs: Shizuku.UserServiceArgs? = null
    private var runRequested = false

    private val permissionResultListener =
        Shizuku.OnRequestPermissionResultListener { requestCode, grantResult ->
            if (requestCode == REQ_PERM &&
                grantResult == PackageManager.PERMISSION_GRANTED
            ) {
                main.post {
                    appendLog(getString(R.string.log_granted))
                    ensureBound()
                }
            } else {
                main.post {
                    appendLog(getString(R.string.log_permission_denied))
                    setStatus(getString(R.string.status_permission_denied), Danger)
                    rootLabel = getString(R.string.root_unknown)
                    rootDetail = getString(R.string.root_unknown_detail)
                }
            }
        }

    private val binderReceivedListener = Shizuku.OnBinderReceivedListener {
        main.post {
            shizukuLabel = getString(R.string.shizuku_connected)
            shizukuDot = Accent
            runEnabled = DeviceProfile.isSupported()
            // 권한이 이미 있으면 상태 조회용으로 서비스를 바인딩해 둔다
            if (checkPermission()) ensureBound() else runCatching {
                Shizuku.requestPermission(REQ_PERM)
            }
        }
    }

    private val binderDeadListener = Shizuku.OnBinderDeadListener {
        main.post {
            shizukuLabel = getString(R.string.shizuku_dead)
            shizukuDot = Danger
            setStatus(getString(R.string.status_shizuku_dead), Danger)
        }
    }

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            if (binder?.pingBinder() != true) return
            val service = IRootService.Stub.asInterface(binder)
            boundService = service
            if (runRequested) {
                runRequested = false
                launch(service)
            } else {
                main.post { updateRootBadge() }
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            boundService = null
        }
    }

    /** Bind the UserService for status queries (and reuse it for runs). */
    private fun ensureBound() {
        if (boundService != null || !checkPermission()) return
        val args = Shizuku.UserServiceArgs(
            ComponentName(packageName, RootService::class.java.name)
        )
            .daemon(false)
            .processNameSuffix("pixeltimer")
            .debuggable(false)
            .version(2)
        boundArgs = args
        runCatching { Shizuku.bindUserService(args, conn) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        autoRoot = getSharedPreferences(Prefs.NAME, MODE_PRIVATE)
            .getBoolean(Prefs.AUTO_ROOT, false)
        if (!DeviceProfile.isSupported() && autoRoot) {
            autoRoot = false
            getSharedPreferences(Prefs.NAME, MODE_PRIVATE)
                .edit().putBoolean(Prefs.AUTO_ROOT, false).apply()
        }
        rootLabel = getString(R.string.root_checking)
        shizukuLabel = getString(R.string.shizuku_checking)
        runLabel = getString(R.string.run_root)

        Shizuku.addBinderReceivedListenerSticky(binderReceivedListener)
        Shizuku.addBinderDeadListener(binderDeadListener)
        Shizuku.addRequestPermissionResultListener(permissionResultListener)

        if (Shizuku.pingBinder()) {
            shizukuLabel = getString(R.string.shizuku_connected)
            shizukuDot = Accent
            runEnabled = DeviceProfile.isSupported()
        } else {
            shizukuLabel = getString(R.string.shizuku_waiting)
            shizukuDot = Warn
            setStatus(getString(R.string.status_shizuku_start), Warn)
        }
        updateRootBadge()
        if (!DeviceProfile.isSupported()) {
            setStatus(getString(R.string.unsupported_profile), Danger)
        }

        setContent {
            MaterialTheme(colorScheme = RootTimerColors) {
                RootScreen(
                    rootLabel = rootLabel,
                    rootDetail = rootDetail,
                    rootDot = rootDot,
                    shizukuLabel = shizukuLabel,
                    shizukuDot = shizukuDot,
                    statusText = statusText,
                    statusColor = statusColor,
                    runLabel = runLabel,
                    runEnabled = runEnabled,
                    isRunning = isRunning,
                    autoRoot = autoRoot,
                    logs = logs,
                    onRun = { showRunConfirm = true },
                    onAutoToggle = { checked ->
                        if (checked && DeviceProfile.isSupported()) showAutoConfirm = true
                        else {
                            autoRoot = false
                            getSharedPreferences(Prefs.NAME, MODE_PRIVATE)
                                .edit().putBoolean(Prefs.AUTO_ROOT, false).apply()
                            appendLog(getString(R.string.log_auto_off))
                        }
                    },
                    onOpenManager = { openManager() },
                )

                if (showRunConfirm) {
                    val alreadyRooted = rootDot == Accent
                    AlertDialog(
                        onDismissRequest = { showRunConfirm = false },
                        title = {
                            Text(
                                stringResource(
                                    if (alreadyRooted) R.string.dialog_rerun_title
                                    else R.string.dialog_run_title
                                ),
                                fontWeight = FontWeight.Bold
                            )
                        },
                        text = {
                            Text(
                                stringResource(
                                    if (alreadyRooted) R.string.dialog_rerun_msg
                                    else R.string.dialog_run_msg
                                )
                            )
                        },
                        confirmButton = {
                            TextButton(onClick = {
                                showRunConfirm = false
                                startRun()
                            }) { Text(stringResource(R.string.dialog_confirm_run), fontWeight = FontWeight.Bold) }
                        },
                        dismissButton = {
                            TextButton(onClick = { showRunConfirm = false }) { Text(stringResource(R.string.dialog_cancel)) }
                        },
                    )
                }

                if (showAutoConfirm) {
                    AlertDialog(
                        onDismissRequest = {
                            showAutoConfirm = false
                            autoRoot = false
                        },
                        title = { Text(stringResource(R.string.dialog_auto_title), fontWeight = FontWeight.Bold) },
                        text = {
                            Text(stringResource(R.string.dialog_auto_msg))
                        },
                        confirmButton = {
                            TextButton(onClick = {
                                showAutoConfirm = false
                                autoRoot = true
                                getSharedPreferences(Prefs.NAME, MODE_PRIVATE)
                                    .edit().putBoolean(Prefs.AUTO_ROOT, true).apply()
                                appendLog(getString(R.string.log_auto_on))
                                requestNotifPermissionIfNeeded()
                            }) { Text(stringResource(R.string.dialog_auto_confirm), fontWeight = FontWeight.Bold) }
                        },
                        dismissButton = {
                            TextButton(onClick = {
                                showAutoConfirm = false
                                autoRoot = false
                            }) { Text(stringResource(R.string.dialog_cancel)) }
                        },
                    )
                }
                if (showManagerDialog) {
                    AlertDialog(
                        onDismissRequest = { showManagerDialog = false },
                        title = { Text(stringResource(R.string.manager_dialog_title), fontWeight = FontWeight.Bold) },
                        text = { Text(stringResource(R.string.manager_dialog_msg)) },
                        confirmButton = {
                            TextButton(onClick = {
                                showManagerDialog = false
                                openManager()
                            }) { Text(stringResource(R.string.manager_dialog_open), fontWeight = FontWeight.Bold) }
                        },
                        dismissButton = {
                            TextButton(onClick = { showManagerDialog = false }) {
                                Text(stringResource(R.string.manager_dialog_later))
                            }
                        },
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        main.post(badgePoller)
    }

    override fun onPause() {
        super.onPause()
        main.removeCallbacks(badgePoller)
    }

    override fun onDestroy() {
        super.onDestroy()
        runCatching { Shizuku.removeBinderReceivedListener(binderReceivedListener) }
        runCatching { Shizuku.removeBinderDeadListener(binderDeadListener) }
        runCatching { Shizuku.removeRequestPermissionResultListener(permissionResultListener) }
        boundArgs?.let { runCatching { Shizuku.unbindUserService(it, conn, true) } }
    }

    private val badgePoller = object : Runnable {
        override fun run() {
            updateRootBadge()
            main.postDelayed(this, 3000)
        }
    }

    private fun updateRootBadge() {
        if (running.get()) return
        val rooted = try {
            File("/proc/modules").useLines { lines ->
                lines.any { it.startsWith("kernelsu ") }
            }
        } catch (_: Exception) {
            null
        } ?: try {
            boundService?.isRooted()
        } catch (_: Exception) {
            null
        } ?: run {
            rootLabel = getString(R.string.root_unknown)
            rootDetail = getString(R.string.root_unknown_detail)
            rootDot = Warn
            return
        }
        if (rooted) {
            rootLabel = getString(R.string.root_rooted)
            rootDetail = getString(R.string.root_rooted_detail)
            rootDot = Accent
            runLabel = getString(R.string.run_reroot)
        } else {
            rootLabel = getString(R.string.root_not_rooted)
            rootDetail = getString(R.string.root_not_detail)
            rootDot = TextSecondary
            runLabel = getString(R.string.run_root)
        }
    }

    private fun requestNotifPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(
                arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF
            )
        }
    }

    private fun startRun() {
        if (!DeviceProfile.isSupported()) {
            setStatus(getString(R.string.unsupported_profile), Danger)
            return
        }
        if (!running.compareAndSet(false, true)) return
        isRunning = true
        runEnabled = false
        runLabel = getString(R.string.run_running)
        logs.clear()
        appendLog(getString(R.string.log_run_started))
        runRequested = true
        if (Shizuku.getVersion() >= 11 && !checkPermission()) {
            setStatus(getString(R.string.status_requesting), Warn)
            runCatching { Shizuku.requestPermission(REQ_PERM) }
                .onFailure {
                    runRequested = false
                    running.set(false)
                    isRunning = false
                    runEnabled = true
                    appendLog("error: ${it.message}")
                    setStatus(getString(R.string.status_request_failed), Danger)
                }
            return
        }
        val svc = boundService
        if (svc != null) {
            runRequested = false
            launch(svc)
        } else {
            ensureBound() // onServiceConnected launches it
        }
    }

    private fun checkPermission(): Boolean =
        Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED

    private fun launch(service: IRootService) {
        setStatus(getString(R.string.status_running), Warn)
        val cb = object : IRootCallback.Stub() {
            override fun onLog(line: String) {
                main.post { appendLog(line) }
            }

            override fun onComplete(exitCode: Int, ksuLoaded: Boolean) {
                main.post {
                    appendLog(getString(R.string.log_exit_fmt, exitCode, ksuLoaded))
                    if (ksuLoaded) {
                        appendLog(getString(R.string.log_root_ok))
                        setStatus(getString(R.string.status_root_ok), Accent)
                        showManagerDialog = true
                    } else if (exitCode == 0) {
                        appendLog(getString(R.string.log_unverified))
                        setStatus(getString(R.string.status_done_unverified), Warn)
                    } else {
                        appendLog(getString(R.string.log_failed))
                        setStatus(getString(R.string.status_failed_fmt, exitCode), Danger)
                    }
                    running.set(false)
                    isRunning = false
                    runEnabled = true
                    updateRootBadge()
                    // Keep the UserService bound: the badge poller uses it to
                    // read /proc/modules (the app uid cannot).  Unbound in
                    // onDestroy.
                }
            }
        }
        runCatching { service.runExploit(cb) }
            .onFailure {
                main.post {
                    appendLog("error: ${it.message}")
                    setStatus(getString(R.string.status_error), Danger)
                    running.set(false)
                    isRunning = false
                    runEnabled = DeviceProfile.isSupported()
                    runLabel = getString(R.string.run_root)
                }
            }
    }

    private fun appendLog(line: String) {
        if (logs.size > 4000) return // hard cap
        logs.add(line)
    }

    private fun openManager() {
        runCatching {
            startActivity(
                Intent(
                    Intent.ACTION_VIEW,
                    Uri.parse(getString(R.string.manager_url))
                )
            )
        }.onFailure {
            appendLog("error opening manager link: ${it.message}")
        }
    }

    private fun setStatus(text: String, color: Color) {
        statusText = text
        statusColor = color
    }

    companion object {
        private const val REQ_PERM = 101
        private const val REQ_NOTIF = 102
    }
}

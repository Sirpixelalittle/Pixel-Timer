package com.roottimer.app

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.content.ServiceConnection
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.work.Worker
import androidx.work.WorkerParameters
import rikka.shizuku.Shizuku
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

object AutoRootNotif {
    private const val CHANNEL = "auto_root"
    private var channelReady = false

    fun post(context: Context, id: Int, title: String, text: String, ongoing: Boolean = false) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (!channelReady) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL, context.getString(R.string.notif_channel),
                    NotificationManager.IMPORTANCE_HIGH
                )
            )
            channelReady = true
        }
        if (Build.VERSION.SDK_INT >= 33 &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            return // silently dropped on 13+ without the grant; the run still happens
        }
        val n = NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(ongoing)
            .setOnlyAlertOnce(true)
            .build()
        runCatching { nm.notify(id, n) }
    }
}

private fun modulesHasKsu(): Boolean = try {
    File("/proc/modules").useLines { lines -> lines.any { it.startsWith("kernelsu ") } }
} catch (_: Exception) {
    false
}

/** Phase 1: wait until Shizuku's binder is up (its own boot receiver starts it). */
class ShizukuWaitWorker(ctx: Context, params: WorkerParameters) :
    Worker(ctx, params) {

    override fun doWork(): Result {
        if (!DeviceProfile.isSupported()) return Result.failure()
        if (modulesHasKsu()) return Result.success() // already rooted, next worker no-ops
        val deadline = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(8)
        while (System.currentTimeMillis() < deadline) {
            if (Shizuku.pingBinder()) return Result.success()
            Thread.sleep(10_000)
        }
        AutoRootNotif.post(
            applicationContext, 1,
            applicationContext.getString(R.string.notif_skip),
            applicationContext.getString(R.string.notif_skip_text)
        )
        // Not a run failure: leave the toggle on for the next boot.
        return Result.failure()
    }
}

/** Phase 2: run the exploit chain through the Shizuku UserService. */
class AutoRootWorker(ctx: Context, params: WorkerParameters) :
    Worker(ctx, params) {

    private fun disableAutoRoot() {
        applicationContext.getSharedPreferences(Prefs.NAME, Context.MODE_PRIVATE)
            .edit().putBoolean(Prefs.AUTO_ROOT, false).apply()
    }

    private fun fail(title: String, text: String): Result {
        AutoRootNotif.post(applicationContext, 1, title, text)
        disableAutoRoot()
        return Result.failure()
    }

    override fun doWork(): Result {
        if (!DeviceProfile.isSupported()) {
            return fail(
                applicationContext.getString(R.string.notif_fail),
                applicationContext.getString(R.string.unsupported_profile)
            )
        }
        if (modulesHasKsu()) {
            AutoRootNotif.post(
                applicationContext, 1,
                applicationContext.getString(R.string.notif_already),
                applicationContext.getString(R.string.notif_already_text)
            )
            return Result.success()
        }
        if (Shizuku.getVersion() < 11 ||
            Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED
        ) {
            return fail(
                applicationContext.getString(R.string.notif_fail),
                applicationContext.getString(R.string.notif_no_perm)
            )
        }

        val latch = CountDownLatch(1)
        var outcome: Pair<Int, Boolean>? = null

        val args = Shizuku.UserServiceArgs(
            ComponentName(applicationContext.packageName, RootService::class.java.name)
        )
            .daemon(false)
            .processNameSuffix("pixeltimer")
            .debuggable(false)
            .version(2)

        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                if (binder?.pingBinder() != true) return
                val service = IRootService.Stub.asInterface(binder)
                val cb = object : IRootCallback.Stub() {
                    override fun onLog(line: String) {
                        if (line.contains("KSU control verified") ||
                            line.contains("PARKED_AFTER_SUCCESS") ||
                            line.contains("[ksu]")
                        ) {
                            AutoRootNotif.post(
                                applicationContext, 1,
                                applicationContext.getString(R.string.notif_auto_started),
                                line, ongoing = true
                            )
                        }
                    }

                    override fun onComplete(exitCode: Int, ksuLoaded: Boolean) {
                        outcome = exitCode to ksuLoaded
                        latch.countDown()
                    }
                }
                runCatching { service.runExploit(cb) }
                    .onFailure {
                        outcome = -1 to false
                        latch.countDown()
                    }
            }

            override fun onServiceDisconnected(name: ComponentName?) {}
        }

        AutoRootNotif.post(
            applicationContext, 1,
            applicationContext.getString(R.string.notif_auto_started),
            applicationContext.getString(R.string.notif_binding), ongoing = true
        )
        runCatching { Shizuku.bindUserService(args, conn) }
            .onFailure {
                return fail(
                applicationContext.getString(R.string.notif_fail),
                applicationContext.getString(R.string.notif_bind_fail_fmt, it.message ?: "?")
            )
            }

        if (!latch.await(9, TimeUnit.MINUTES)) {
            runCatching { Shizuku.unbindUserService(args, conn, true) }
            return fail(
                applicationContext.getString(R.string.notif_fail),
                applicationContext.getString(R.string.notif_timeout)
            )
        }
        runCatching { Shizuku.unbindUserService(args, conn, true) }

        val (code, loaded) = outcome ?: (-1 to false)
        return if (loaded) {
            AutoRootNotif.post(
                applicationContext, 1,
                applicationContext.getString(R.string.notif_success),
                applicationContext.getString(R.string.notif_success_text)
            )
            Result.success()
        } else {
            fail(
                applicationContext.getString(R.string.notif_fail_exit_fmt, code),
                applicationContext.getString(R.string.notif_disabled_hint)
            )
        }
    }
}

package com.roottimer.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/**
 * Boots the auto-root chain when RECEIVE_BOOT_COMPLETED fires and the user
 * enabled the toggle.  The chain is two chained WorkManager jobs:
 *
 *   ShizukuWaitWorker  - waits for Shizuku's binder (it starts on its own
 *                        boot receiver when the user set wireless debugging
 *                        to auto-start), up to 8 minutes.
 *   AutoRootWorker     - binds the UserService and runs the exploit, with a
 *                        notification at each phase.  A failed run disables
 *                        the toggle so a bad build cannot boot-loop the
 *                        phone (DirtyFrag's failed-run interlock idea).
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val prefs = context.getSharedPreferences(Prefs.NAME, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(Prefs.AUTO_ROOT, false)) return
        if (!DeviceProfile.isSupported()) {
            prefs.edit().putBoolean(Prefs.AUTO_ROOT, false).apply()
            return
        }

        val wait = OneTimeWorkRequestBuilder<ShizukuWaitWorker>()
            .setInitialDelay(45, TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(context)
            .beginUniqueWork("auto_root", ExistingWorkPolicy.REPLACE, wait)
            .then(OneTimeWorkRequestBuilder<AutoRootWorker>().build())
            .enqueue()
    }
}

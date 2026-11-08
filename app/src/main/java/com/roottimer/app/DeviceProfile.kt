package com.roottimer.app

import android.os.Build
import android.system.Os
import android.system.OsConstants

/** Exact profile used to derive the native payload's kernel offsets. */
object DeviceProfile {
    const val DEVICE = "husky"
    const val KERNEL = "6.1.162-android14-11-g9dd05ae3a1de-ab16261587"
    const val PAGE_SIZE = 4096L

    fun isSupported(): Boolean = try {
        Build.DEVICE == DEVICE && Os.uname().release == KERNEL &&
            Os.sysconf(OsConstants._SC_PAGESIZE) == PAGE_SIZE
    } catch (_: Exception) {
        false
    }
}

package com.roottimer.app

import android.content.Context
import android.os.Process
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Runs the Pixel 8 Pro payload through Shizuku's shell UserService. */
class RootService(private val context: Context) : IRootService.Stub() {

    private val running = AtomicBoolean(false)

    companion object {
        private const val WORK_DIR = "/data/local/tmp/pixel-timer-app"
        private const val ASSET_KSUD = "ksud-pixel"
        private const val WAIT_MINUTES = 8L
    }

    override fun isReady(): Boolean = Process.myUid() == 2000 && DeviceProfile.isSupported()

    override fun isRooted(): Boolean = moduleLive()

    override fun destroy() {}

    private fun moduleLive(): Boolean = try {
        File("/proc/modules").useLines { lines ->
            lines.any { it.startsWith("kernelsu ") }
        }
    } catch (_: Exception) {
        false
    }

    override fun runExploit(callback: IRootCallback?) {
        if (callback == null) return
        if (!running.compareAndSet(false, true)) {
            callback.onLog("error: another run is already in progress")
            callback.onComplete(1, false)
            return
        }
        Thread({
            var code = 1
            try {
                code = runChain(callback)
            } catch (e: Exception) {
                log(callback, "error: ${e.message}")
            } finally {
                runCatching { callback.onComplete(code, code == 0 && moduleLive()) }
                running.set(false)
            }
        }, "pixel-timer-runner").start()
    }

    private fun log(callback: IRootCallback, line: String) {
        runCatching { callback.onLog(line) }
    }

    private fun runChain(callback: IRootCallback): Int {
        if (Process.myUid() != 2000) {
            log(callback, "error: Shizuku shell (uid 2000) is required")
            return 1
        }
        if (!DeviceProfile.isSupported()) {
            log(callback, "error: unsupported device, kernel, or page size; Pixel 8 Pro profile only")
            return 2
        }
        if (moduleLive()) {
            log(callback, "KernelSU Next is already loaded")
            return 0
        }

        val timer = File(context.applicationInfo.nativeLibraryDir, "libtimer.so")
        if (!timer.isFile) {
            log(callback, "error: Pixel payload is missing")
            return 1
        }
        val workDir = File(WORK_DIR)
        if (!workDir.isDirectory && !workDir.mkdirs()) {
            log(callback, "error: cannot create $WORK_DIR")
            return 1
        }
        val ksud = File(workDir, "ksud")
        try {
            context.assets.open(ASSET_KSUD).use { input ->
                ksud.outputStream().use { output -> input.copyTo(output) }
            }
            if (!ksud.setReadable(true, true) || !ksud.setExecutable(true, true)) {
                log(callback, "error: cannot set ksud permissions")
                return 1
            }
        } catch (e: Exception) {
            log(callback, "error: cannot stage KernelSU Next: ${e.message}")
            return 1
        }

        log(callback, "Pixel 8 Pro profile matched; starting root and KernelSU Next load")
        val proc = ProcessBuilder(timer.absolutePath, "--install")
            .directory(workDir)
            .redirectErrorStream(true)
            .start()
        val reader = Thread({
            try {
                proc.inputStream.bufferedReader().useLines { lines ->
                    for (line in lines) log(callback, line)
                }
            } catch (_: Exception) {}
        }, "pixel-timer-log")
        reader.isDaemon = true
        reader.start()

        if (!proc.waitFor(WAIT_MINUTES, TimeUnit.MINUTES)) {
            // The native payload may be holding a reclaimed kernel page.
            // Leave it running; a reboot is the safe recovery path.
            log(callback, "error: timed out; reboot before trying again")
            return 4
        }
        val exit = proc.exitValue()
        reader.join(1000)
        if (exit != 0) {
            log(callback, "error: Pixel payload exited $exit")
            return exit
        }
        if (!moduleLive()) {
            log(callback, "error: payload finished but KernelSU Next is not loaded")
            return 5
        }
        log(callback, "KSU_LOADED")
        return 0
    }
}

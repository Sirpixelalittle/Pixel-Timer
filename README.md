# Pixel Timer

Pixel Timer is an Android app for a temporary root attempt on the **Pixel 8 Pro** using CVE-2026-98260. It adapts the [SamTimer](https://github.com/yoro1836/SamTimer) app interface to the Pixel 8 Pro proof of concept in this project.

**Only the Pixel 8 Pro (husky), stock build CP3A.261005.005, kernel `6.1.162-android14-11-g9dd05ae3a1de-ab16261587`, 4 KiB pages has been tested.** The app refuses to run on any other device or kernel. The Pixel 8 Pro owner confirmed the full app flow, including KernelSU Next loading, works end to end on this profile.

Root is temporary and clears on reboot. A failed attempt can leave the device unstable until a reboot. Use only on a device you own or are authorized to test.

## What the app does

1. Uses Shizuku's shell UserService (uid 2000) to run the Pixel 8 Pro native payload.
2. Checks the exact device, kernel release, and page size before the payload touches tracing or timers. The native payload repeats the check.
3. Gains a temporary root worker and attempts to late-load the bundled KernelSU Next v3.4.2 `ksud` for `android14-6.1`.
4. Reports success only if the `kernelsu` module appears in `/proc/modules`.

The app includes an optional auto-root switch. It waits for Shizuku after reboot, and disables itself if a run fails or the device profile changes.

## Requirements

- The tested Pixel 8 Pro build and kernel above.
- Shizuku running through wireless debugging, with permission granted to Pixel Timer.
- The [KernelSU Next v3.4.2 manager](https://github.com/KernelSU-Next/KernelSU-Next/releases/tag/v3.4.2) to grant `su` after the module loads. Use the manager from the same release as the bundled `ksud`.

## Build and install

Open this directory in Android Studio, or run:

```sh
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

The build compiles `app/src/main/cpp/timer.c` with its local `offsets.h` and `pixel_main.inc` into an ARM64 payload. Set `ANDROID_NDK_HOME` or `ndk.dir` if the Android NDK is not found. The app version remains **1.3** (`versionCode 4`).

Start Shizuku, launch Pixel Timer, and tap **Root now**. Wait for the result before attempting another run. If the app times out or reports a failed root attempt, reboot before retrying. The manager can be installed from the link shown after a successful load.

## Source and credits

- Android app: adapted from [SamTimer](https://github.com/yoro1836/SamTimer), including its Shizuku and Compose structure. The forked app also credited RiosWesley and fntz1.
- Native timer exploit: adapted from SamTimer's CVE-2026-98260 code, with the Pixel 8 Pro profile and temporary root worker from the local proof of concept. The original exploit credits woshigenm/CVE-2026-98260 and the aurora port.
- Root manager and late-load binary: [KernelSU Next](https://github.com/KernelSU-Next/KernelSU-Next).

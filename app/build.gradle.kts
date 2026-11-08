plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ─────────────────────────────────────────────────────────────────────────
// Pixel 8 Pro payload build: timer.c + offsets.h + pixel_main.inc → libtimer.so
//
// The CVE-2026-98260 binary ships inside the APK and is executed straight
// from nativeLibraryDir (useLegacyPackaging keeps it uncompressed).  Building
// it from Gradle keeps the payload in lockstep with the app: a plain
// `./gradlew assembleDebug` always produces a fresh binary.  The flags are
// exactly the ones the exploit was verified with; keep them in sync with any
// manual build.
// ─────────────────────────────────────────────────────────────────────────

fun ndkHome(): String? {
    val env = System.getenv("ANDROID_NDK_HOME")
    if (!env.isNullOrBlank()) return env
    val lp = rootProject.file("local.properties")
    val lines = if (lp.exists()) lp.readLines() else emptyList<String>()
    val ndkDirProp = lines.firstOrNull { it.startsWith("ndk.dir=") }
        ?.substringAfter("=")?.trim()
    if (!ndkDirProp.isNullOrBlank()) return ndkDirProp
    val sdkDirProp = lines.firstOrNull { it.startsWith("sdk.dir=") }
        ?.substringAfter("=")?.trim()
    val sdkDir = if (!sdkDirProp.isNullOrBlank()) sdkDirProp
        else System.getenv("ANDROID_SDK_ROOT")
    if (sdkDir != null) {
        val best = file("$sdkDir/ndk").listFiles()
            ?.filter { it.isDirectory }
            ?.maxByOrNull { it.name }
        if (best != null) return best.absolutePath
    }
    val home = System.getProperty("user.home")
    return listOf(
        "$home/Projects/susfs/kernel_pixel_6.1/prebuilts/ndk-r23",
        "$home/android-ndk-r27c",
        "$home/Android/Sdk/ndk/27.2.12479018"
    ).firstOrNull { file(it).exists() }
}

val buildPayload by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds the timer exploit payload into jniLibs (arm64)"
    val src = file("src/main/cpp/timer.c")
    val out = file("src/main/jniLibs/arm64-v8a/libtimer.so")
    inputs.files(src, file("src/main/cpp/offsets.h"), file("src/main/cpp/pixel_main.inc"))
    outputs.file(out)
    doFirst {
        val ndk = ndkHome()
            ?: throw GradleException(
                "NDK not found — set ANDROID_NDK_HOME or ndk.dir in local.properties"
            )
        val windows = System.getProperty("os.name").startsWith("Windows")
        val host = if (windows) "windows-x86_64" else "linux-x86_64"
        val cc = "$ndk/toolchains/llvm/prebuilt/$host/bin/aarch64-linux-android31-clang" +
            if (windows) ".cmd" else ""
        if (!file(cc).exists()) throw GradleException("clang not found: $cc")
        out.parentFile.mkdirs()
        logger.lifecycle("payload: $src -> $out")
        val args = listOf(
            "-O2", "-std=gnu11", "-static",
            "-Wall", "-Wextra", "-Wno-unused-parameter",
            "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
            src.absolutePath, "-o", out.absolutePath
        )
        if (windows)
            commandLine(listOf("cmd", "/c", cc) + args)
        else
            commandLine(listOf(cc) + args)
    }
}

android {
    namespace = "com.roottimer.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.pixeltimer.app"
        minSdk = 31
        targetSdk = 34
        versionCode = 4
        versionName = "1.3"
    }

    buildTypes {
        val releaseKs = rootProject.file("app/keystore/release.jks")
        signingConfigs {
            if (releaseKs.exists()) {
                create("release") {
                    storeFile = releaseKs
                    storePassword = "samtimer"
                    keyAlias = "samtimer"
                    keyPassword = "samtimer"
                }
            }
        }
        release {
            isMinifyEnabled = false
            signingConfig = if (releaseKs.exists())
                signingConfigs.getByName("release")
            else
                signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        aidl = true
        compose = true
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    val shizukuVersion = "13.1.5"
    implementation("dev.rikka.shizuku:api:$shizukuVersion")
    implementation("dev.rikka.shizuku:provider:$shizukuVersion")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.work:work-runtime-ktx:2.9.1")

    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    debugImplementation("androidx.compose.ui:ui-tooling")
}

// The payload must exist before anything packages jniLibs.
tasks.named("preBuild") { dependsOn(buildPayload) }

// clean deletes build outputs; the generated payload lives in jniLibs.
tasks.named<Delete>("clean") {
    delete(file("src/main/jniLibs/arm64-v8a/libtimer.so"))
}

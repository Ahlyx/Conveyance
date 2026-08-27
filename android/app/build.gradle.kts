import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
}

// ---------------------------------------------------------------------------
// Phase 10.1 UniFFI spike — Rust crypto bridge.
//
// Two Cargo invocations feed the Android build:
//   1. `cargo ndk` cross-compiles conveyance-crypto-ffi to a .so per ABI,
//      dropped straight into src/main/jniLibs/<abi>/.
//   2. `uniffi-bindgen` reads one of those .so files and emits the Kotlin
//      bindings that call into it (library mode — no .udl).
// preBuild depends on (2), which depends on (1). Both are wiped by
// `clean` via their declared outputs.
//
// The whole block is self-contained and removable: if the spike is
// abandoned, deleting it plus the jniLibs dir and the generated-source
// srcDir reverts the app to pure Kotlin.
// ---------------------------------------------------------------------------
val rustWorkspaceRoot: File = rootProject.projectDir.parentFile
val ffiCrate = "conveyance-crypto-ffi"
val ffiLibName = "libconveyance_crypto_ffi.so"

// ABI policy for v1 (see CONVEYANCE_PHASES.md 10.1): arm64-v8a is the
// real-device target, x86_64 is what CI's emulator runs. No 32-bit.
val androidAbis = listOf("arm64-v8a", "x86_64")

val jniLibsDir: File = file("src/main/jniLibs")
val uniffiBindingsDir: Provider<Directory> = layout.buildDirectory.dir("generated/uniffi")

val cargoNdkBuild by tasks.registering(Exec::class) {
    group = "rust"
    description = "Cross-compiles $ffiCrate to a .so for ${androidAbis.joinToString()}."
    workingDir = rustWorkspaceRoot
    commandLine(
        buildList {
            add("cargo"); add("ndk")
            androidAbis.forEach { add("-t"); add(it) }
            add("-o"); add(jniLibsDir.absolutePath)
            add("build"); add("--release"); add("-p"); add(ffiCrate)
        },
    )
    inputs.dir(rustWorkspaceRoot.resolve("crates/conveyance-crypto-ffi/src"))
    inputs.dir(rustWorkspaceRoot.resolve("crates/conveyance-crypto/src"))
    inputs.file(rustWorkspaceRoot.resolve("Cargo.lock"))
    outputs.dir(jniLibsDir)
}

val generateUniffiBindings by tasks.registering(Exec::class) {
    group = "rust"
    description = "Generates Kotlin bindings for $ffiCrate from the built .so."
    dependsOn(cargoNdkBuild)
    workingDir = rustWorkspaceRoot
    val referenceSo = jniLibsDir.resolve("arm64-v8a/$ffiLibName")
    commandLine(
        "cargo", "run", "--release", "-p", ffiCrate, "--bin", "uniffi-bindgen", "--",
        "generate",
        "--library", referenceSo.absolutePath,
        "--language", "kotlin",
        "--no-format",
        "--out-dir", uniffiBindingsDir.get().asFile.absolutePath,
    )
    inputs.file(referenceSo)
    outputs.dir(uniffiBindingsDir)
}

tasks.matching { it.name == "preBuild" }.configureEach {
    dependsOn(generateUniffiBindings)
}

android {
    namespace = "com.ahlyxlabs.conveyance"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "com.ahlyxlabs.conveyance"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            // No shrinking yet: there is nothing to shrink, and enabling
            // R8 now would only add rules churn as real code lands.
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        // BuildConfig is used by the smoke test (APPLICATION_ID) and by
        // later phases to gate developer-only surfaces on BuildConfig.DEBUG.
        buildConfig = true
    }

    // The UniFFI-generated Kotlin lands here (see the Rust block at the
    // top of this file); treat it as a source root.
    sourceSets["main"].kotlin.srcDir(uniffiBindingsDir)

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.core.splashscreen)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)

    // Phase 10.1 UniFFI spike. The generated crypto bindings call through
    // JNA; the @aar variant carries JNA's per-ABI native dispatch libs
    // (a plain jar resolves but crashes at runtime on device).
    implementation("net.java.dev.jna:jna:${libs.versions.jna.get()}@aar")

    testImplementation(libs.junit)

    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
}

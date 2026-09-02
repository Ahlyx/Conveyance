import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
}

// ---------------------------------------------------------------------------
// Rust bridge — conveyance-crypto-ffi cross-compiled + UniFFI bindings.
//
// Introduced in phase 10.1 (crypto spike); rewritten to a VARIANT SPLIT in
// phase 10.4. Per variant, three Cargo steps feed the Android build, hung
// off pre<Variant>Build:
//   * cargoNdkBuild<Variant>       — `cargo ndk` cross-compiles the ffi
//                                    crate to a .so per ABI, into
//                                    src/<variant>/jniLibs/<abi>/.
//   * cargoBuildHostFfi<Variant>   — builds the ffi crate for the *host*
//                                    so uniffi-bindgen can read its
//                                    metadata (its library reader can't
//                                    parse a foreign-ABI .so on a Windows
//                                    host).
//   * generateUniffiBindings<Var>  — runs uniffi-bindgen (library mode, no
//                                    .udl) against that host lib, into
//                                    build/generated/uniffi/<variant>,
//                                    wired as sourceSets["<variant>"].
//
// Why the split (phase 10.4): the DEBUG variant enables
// `conveyance-crypto-ffi/test-vectors`, which exports
// `noiseInitiateWithFixedEphemeral` for the Noise handshake parity suite
// (fixed ephemeral -> deterministic handshake bytes). It builds the DEV
// profile because conveyance-noise refuses to compile `test-vectors` with
// `debug_assertions` off. The RELEASE variant is the optimized .so with
// no test-only surface. Each variant carries its own bindings so the
// generated Kotlin always matches the .so it loads (UniFFI's runtime
// contract checksum would otherwise fault). CI builds only the debug
// variant. `./gradlew build` locally runs both and will thrash the shared
// cargo target dir — assemble a single variant if that matters.
//
// The whole block is self-contained: deleting it plus src/*/jniLibs
// reverts the app to pure Kotlin.
// ---------------------------------------------------------------------------
val rustWorkspaceRoot: File = rootProject.projectDir.parentFile
val ffiCrate = "conveyance-crypto-ffi"

// ABI policy for v1 (see CONVEYANCE_PHASES.md 10.1): arm64-v8a is the
// real-device target, x86_64 is what CI's emulator runs. No 32-bit.
val androidAbis = listOf("arm64-v8a", "x86_64")

val uniffiConfig: File = rustWorkspaceRoot.resolve("crates/$ffiCrate/uniffi.toml")

fun hostFfiLib(profileDir: String): File {
    val os = System.getProperty("os.name").lowercase()
    val (prefix, ext) = when {
        os.contains("win") -> "" to "dll"
        os.contains("mac") -> "lib" to "dylib"
        else -> "lib" to "so"
    }
    return rustWorkspaceRoot.resolve("target/$profileDir/${prefix}conveyance_crypto_ffi.$ext")
}

data class RustVariant(val name: String, val release: Boolean, val features: List<String>) {
    val jniLibs: File get() = file("src/$name/jniLibs")
    val bindings: Provider<Directory> get() = layout.buildDirectory.dir("generated/uniffi/$name")
    val hostProfile: String get() = if (release) "release" else "debug"
}

val rustVariants = listOf(
    RustVariant("debug", release = false, features = listOf("$ffiCrate/test-vectors")),
    RustVariant("release", release = true, features = emptyList()),
)

val commonRustInputs: Action<Exec> = Action {
    inputs.dir(rustWorkspaceRoot.resolve("crates/conveyance-crypto-ffi/src"))
    inputs.dir(rustWorkspaceRoot.resolve("crates/conveyance-crypto/src"))
    inputs.dir(rustWorkspaceRoot.resolve("crates/conveyance-noise/src"))
    inputs.file(rustWorkspaceRoot.resolve("Cargo.lock"))
}

rustVariants.forEach { v ->
    val featureArgs = v.features.flatMap { listOf("--features", it) }

    val ndk = tasks.register<Exec>("cargoNdkBuild${v.name.replaceFirstChar { it.uppercase() }}") {
        group = "rust"
        description = "Cross-compiles $ffiCrate (${v.name}) to a .so for ${androidAbis.joinToString()}."
        workingDir = rustWorkspaceRoot
        commandLine(
            buildList {
                add("cargo"); add("ndk")
                androidAbis.forEach { add("-t"); add(it) }
                add("-o"); add(v.jniLibs.absolutePath)
                add("build"); if (v.release) add("--release")
                add("-p"); add(ffiCrate)
                addAll(featureArgs)
            },
        )
        commonRustInputs.execute(this)
        outputs.dir(v.jniLibs)
    }

    val hostBuild = tasks.register<Exec>("cargoBuildHostFfi${v.name.replaceFirstChar { it.uppercase() }}") {
        group = "rust"
        description = "Builds $ffiCrate (${v.name}) for the host so uniffi-bindgen can read its metadata."
        workingDir = rustWorkspaceRoot
        commandLine(buildList { add("cargo"); add("build"); if (v.release) add("--release"); add("-p"); add(ffiCrate); addAll(featureArgs) })
        commonRustInputs.execute(this)
        outputs.file(hostFfiLib(v.hostProfile))
    }

    tasks.register<Exec>("generateUniffiBindings${v.name.replaceFirstChar { it.uppercase() }}") {
        group = "rust"
        description = "Generates Kotlin bindings for $ffiCrate (${v.name})."
        dependsOn(hostBuild)
        workingDir = rustWorkspaceRoot
        // uniffi-bindgen auto-discovers crates/<ffiCrate>/uniffi.toml from the
        // library's metadata. That file sets `android = true` so the generated
        // object cleaner uses the JNA path on <API 34 and guards the
        // java.lang.ref.Cleaner path with @RequiresApi — lintDebug then passes
        // at minSdk 30.
        commandLine(
            "cargo", "run", *(if (v.release) arrayOf("--release") else emptyArray()),
            "-p", ffiCrate, *featureArgs.toTypedArray(), "--bin", "uniffi-bindgen", "--",
            "generate",
            "--library", hostFfiLib(v.hostProfile).absolutePath,
            "--language", "kotlin",
            "--no-format",
            "--out-dir", v.bindings.get().asFile.absolutePath,
        )
        inputs.file(hostFfiLib(v.hostProfile))
        inputs.file(uniffiConfig)
        outputs.dir(v.bindings)
    }

    tasks.matching { it.name == "pre${v.name.replaceFirstChar { it.uppercase() }}Build" }.configureEach {
        dependsOn(ndk, "generateUniffiBindings${v.name.replaceFirstChar { it.uppercase() }}")
    }
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

        testInstrumentationRunner = "com.ahlyxlabs.conveyance.HiltTestRunner"

        // Only ship ABIs the Rust bridge is built for (see androidAbis
        // above). Without this the APK still carries JNA's .so for every
        // ABI it publishes, on which our libconveyance_crypto_ffi.so
        // would be missing.
        ndk {
            abiFilters += androidAbis
        }
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

    // Per-variant UniFFI bindings + jniLibs (see the Rust block at the top
    // of this file). Debug's bindings carry the `test-vectors` surface;
    // release's do not. jniLibs are picked up from src/<variant>/jniLibs
    // automatically.
    rustVariants.forEach { v ->
        sourceSets[v.name].kotlin.srcDir(v.bindings)
    }

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

    implementation(libs.kotlinx.coroutines.android)

    // Phase 10.1 UniFFI spike. The generated crypto bindings call through
    // JNA; the @aar variant carries JNA's per-ABI native dispatch libs
    // (a plain jar resolves but crashes at runtime on device).
    implementation("net.java.dev.jna:jna:${libs.versions.jna.get()}@aar")

    // Phase 10.2b encrypted storage. Room over SQLCipher: the app never
    // opens an unencrypted DB.
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)
    implementation(libs.androidx.sqlite)
    implementation(libs.sqlcipher.android)

    testImplementation(libs.junit)
    // Real org.json for the framing fixture-parity suite (android.jar's
    // stub throws on the JVM). Must precede any android.jar on the
    // unit-test classpath, which testImplementation does.
    testImplementation(libs.org.json)
    testImplementation(libs.kotlinx.coroutines.test)

    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.hilt.android.testing)
    kspAndroidTest(libs.hilt.compiler)
}

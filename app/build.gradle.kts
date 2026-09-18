import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
}

val keystoreProps = Properties().also { props ->
    val propsFile = rootProject.file("keystore.properties")
    if (propsFile.exists()) propsFile.inputStream().use(props::load)
}
val hasReleaseKey = keystoreProps["storeFile"]?.let { rootProject.file(it).exists() } == true

// Export Room schemas so migrations can be verified by MigrationTestHelper.
ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

android {
    namespace = "dev.alsatianconsulting.pocketpcap"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.alsatianconsulting.pocketpcap"
        minSdk = 29
        targetSdk = 36
        versionCode = 7
        versionName = "0.1.6"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // arm64 only, deliberately. The bundled tshark/dumpcap/editcap/mergecap and
        // their whole shared-object closure are an aarch64 Termux build, so on any
        // other ABI the app installs and then cannot decode anything - the other ABIs
        // were never usable, they only arrived as transitive stubs from dependencies.
        //
        // It is also what keeps the app 16 KB page-size compliant: every arm64
        // library here is built with p_align >= 16384, while the other ABIs only ever
        // arrived as transitive stubs and the x86_64 libgojni.so among them was
        // aligned to 4096, which Play rejects.
        ndk { abiFilters += "arm64-v8a" }
    }

    sourceSets {
        // Bundle exported Room schemas as test assets for migration testing.
        getByName("androidTest").assets.srcDir("$projectDir/schemas")
    }

    signingConfigs {
        if (hasReleaseKey) {
            create("release") {
                storeFile = rootProject.file(keystoreProps["storeFile"] as String)
                storePassword = keystoreProps["storePassword"] as String?
                keyAlias = keystoreProps["keyAlias"] as String?
                keyPassword = keystoreProps["keyPassword"] as String?
                // Be explicit rather than relying on defaults. v1 (JAR) is only needed
                // below API 24 and minSdk is 29, so it is off; v3 carries the key
                // rotation lineage, which matters for an app meant to outlive one key.
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            // R8 full mode: tree-shakes the 40MB+ material-icons-extended dex down
            // to only the ~30 icons we reference, and shrinks unused resources.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // The real release key when the machine has it, the debug key otherwise so
            // the shrunk APK is still directly installable for on-device verification.
            signingConfig = signingConfigs.getByName(if (hasReleaseKey) "release" else "debug")
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = "11"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        // The bundled tshark and its libraries must exist as real files on disk
        // for the app to exec them; with the modern packaging they are mapped
        // straight out of the APK and cannot be executed, only dlopen'd. Legacy
        // packaging compresses them in the APK and has the installer extract them
        // into the native library directory, which is the one place an
        // unprivileged app is allowed to execute from.
        jniLibs.useLegacyPackaging = true
    }

    androidResources {
        noCompress += "zip"
    }
}

/**
 * GPL-3 requires the licence to accompany the program, and PocketPCAP ships GPL
 * and LGPL binaries whose notices have to travel with the APK too. The repository
 * LICENSE and THIRD-PARTY-NOTICES.md are copied into assets at build time so the
 * in-app copy under Settings > About > Licences can never drift from the real one.
 *
 * Registered through the variant API rather than a plain srcDir: assets generated
 * by a task have several consumers beyond asset merging (lint builds a model from
 * them too), and addGeneratedSourceDirectory declares the provenance once so AGP
 * wires every one of them.
 */
abstract class CopyLicenseAssets : DefaultTask() {
    @get:InputFiles abstract val sourceFiles: ConfigurableFileCollection

    @get:OutputDirectory abstract val outputDir: DirectoryProperty

    @TaskAction
    fun copy() {
        val target = outputDir.get().asFile.resolve("licenses")
        target.deleteRecursively()
        target.mkdirs()
        sourceFiles.forEach { it.copyTo(target.resolve(it.name), overwrite = true) }
    }
}

val copyLicenseAssets = tasks.register<CopyLicenseAssets>("copyLicenseAssets") {
    sourceFiles.from(rootProject.file("LICENSE"), rootProject.file("THIRD-PARTY-NOTICES.md"))
}

androidComponents {
    onVariants { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(
            copyLicenseAssets,
            CopyLicenseAssets::outputDir,
        )
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.kotlinx.coroutines.android)

    // Room persistence (endpoint aliases, recent + saved filters).
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)

    // Rootless VPN pass-through: TUN packets -> local direct SOCKS relay.
    //
    // Built from source by scripts/build-tun2socks-aar.sh, not pulled from Maven.
    // The prebuilt com.ooimi.library:tun2socks:1.0.4 this replaces was last
    // published in November 2023 and its libgojni.so records NDK r19c, which Play
    // rejects as a 16 KB page-size crash risk. The archive is gitignored; run that
    // script once on a fresh checkout, the same as the tshark bundle.
    implementation(files("libs/tun2socks.aar"))

    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)

    // Local JVM unit tests (suggestion engine, OUI parsing, filter builders).
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    // Real org.json impl so GeoIP/RDAP parser tests run on the JVM (the android.jar
    // org.json is a stub that throws "not mocked" in unit tests).
    testImplementation("org.json:json:20240303")

    // Instrumented tests (Room migrations + DAO persistence, Compose UI).
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.room.testing)
    androidTestImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)
}

// The repository may live in a cloud-synced folder that creates numbered copies
// inside connected-test result directories while Gradle snapshots them. Device
// tests are inherently non-cacheable, so avoid output-state hashing for these tasks.
tasks.matching { it.name.startsWith("connected") && it.name.endsWith("AndroidTest") }.configureEach {
    doNotTrackState("Connected device results are volatile and may be cloud-synced")
}

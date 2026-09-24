import org.gradle.api.tasks.Exec

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val generatedJniLibs = layout.buildDirectory.dir("generated/prwJniLibs")

val buildPrwNative by tasks.registering(Exec::class) {
    workingDir(rootProject.file("native"))
    environment("ANDROID_NDK_HOME", "${System.getenv("ANDROID_HOME")}/ndk/28.2.13676358")
    environment("ANDROID_NDK_ROOT", "${System.getenv("ANDROID_HOME")}/ndk/28.2.13676358")
    commandLine(
        "cargo", "+1.97.1", "ndk",
        "--platform", "29",
        "-t", "arm64-v8a",
        "-t", "x86_64",
        "-o", generatedJniLibs.get().asFile.absolutePath,
        "build", "--locked", "--release",
    )
}

android {
    namespace = "com.privateworkspace.prw"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.privateworkspace.prw"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-dev"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        compose = true
        buildConfig = false
    }

    sourceSets["main"].jniLibs.directories.add(generatedJniLibs.get().asFile.absolutePath)

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

tasks.named("preBuild").configure {
    dependsOn(buildPrwNative)
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.06.00")
    implementation(composeBom)
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.10.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    testImplementation("junit:junit:4.13.2")
}

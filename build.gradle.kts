plugins {
    // this is necessary to avoid the plugins to be loaded multiple times
    // in each subproject's classloader
    alias(libs.plugins.androidApplication) apply false
    alias(libs.plugins.androidLibrary) apply false
    alias(libs.plugins.composeMultiplatform) apply false
    alias(libs.plugins.composeCompiler) apply false
    alias(libs.plugins.kotlinMultiplatform) apply false
}

subprojects {
    plugins.withId("org.jetbrains.kotlin.multiplatform") {
        val ext = extensions.findByName("kotlin")
        ext?.javaClass?.getMethod("jvmToolchain", Int::class.java)?.invoke(ext, 17)
    }
}

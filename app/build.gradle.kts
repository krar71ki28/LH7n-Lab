plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.lh7n.lab"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.lh7n.lab"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }
}

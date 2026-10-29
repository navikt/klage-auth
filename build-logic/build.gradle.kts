plugins {
    `kotlin-dsl`
}

// Plugin versions for the whole build. The modules apply the plugins by id only.
val kotlinVersion = "2.4.20"
val ktlintPluginVersion = "14.2.0"
val detektPluginVersion = "2.0.0-alpha.6"

dependencies {
    implementation(plugin(id = "org.jetbrains.kotlin.jvm", version = kotlinVersion))
    implementation(plugin(id = "org.jetbrains.kotlin.plugin.spring", version = kotlinVersion))
    implementation(plugin(id = "org.jlleitschuh.gradle.ktlint", version = ktlintPluginVersion))
    implementation(plugin(id = "dev.detekt", version = detektPluginVersion))
}

fun plugin(
    id: String,
    version: String,
) = "$id:$id.gradle.plugin:$version"

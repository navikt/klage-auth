import dev.detekt.gradle.Detekt
import dev.detekt.gradle.plugin.getSupportedKotlinVersion
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jlleitschuh.gradle.ktlint.reporter.ReporterType

// Shared setup for every published module in this build.

plugins {
    id("org.jetbrains.kotlin.jvm")
    `java-library`
    `maven-publish`
    id("org.jlleitschuh.gradle.ktlint")
    id("dev.detekt")
}

val ktlintVersion = "1.8.0"

// Must follow the Spring Boot version the consuming apps use.
val springBootVersion = "4.1.2"

group = "no.nav.klage"
version = providers.gradleProperty("version").getOrElse("local-build")

repositories {
    mavenCentral()
}

dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
    withSourcesJar()
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_21)
        freeCompilerArgs.add("-Xjsr305=strict")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

ktlint {
    version.set(ktlintVersion)
    ignoreFailures.set(false)
    reporters {
        reporter(ReporterType.PLAIN)
        reporter(ReporterType.CHECKSTYLE)
    }
    filter {
        exclude { it.file.path.contains("${File.separator}build${File.separator}") }
    }
}

detekt {
    config.setFrom(isolated.rootProject.projectDirectory.file("config/detekt/detekt.yml"))
    buildUponDefaultConfig.set(true)
    ignoreFailures.set(false)
}

// The Spring Boot BOM manages the Kotlin version, which would force the linters onto the
// project's Kotlin compiler. Both are built against a specific compiler version.
configurations.matching { it.name == "detekt" }.configureEach {
    resolutionStrategy.eachDependency {
        if (requested.group == "org.jetbrains.kotlin") {
            useVersion(getSupportedKotlinVersion())
        }
    }
}

// NamedArguments only reports when detekt runs with a compile classpath, so the analysis
// aware tasks are wired into `check` and the plain one is disabled.
tasks.named("detekt") {
    enabled = false
}

tasks.withType<Detekt>().configureEach {
    jvmTarget.set(JvmTarget.JVM_21.target)
    reports {
        html.required.set(true)
        checkstyle.required.set(true)
        sarif.required.set(false)
        markdown.required.set(false)
    }
}

tasks.named("check") {
    dependsOn("detektMain", "detektTest")
}

publishing {
    repositories {
        maven {
            url = uri("https://maven.pkg.github.com/navikt/klage-auth")
            credentials {
                username = System.getenv("GITHUB_USERNAME")
                password = System.getenv("GITHUB_PASSWORD")
            }
        }
    }
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            // Publish the versions resolved from the Spring Boot BOM, so the POM is
            // usable without the BOM.
            versionMapping {
                usage("java-api") { fromResolutionOf("runtimeClasspath") }
                usage("java-runtime") { fromResolutionResult() }
            }
            pom {
                name.set(project.name)
                description.set("Token validation for klage apps")
                url.set("https://github.com/navikt/klage-auth")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/navikt/klage-auth.git")
                    developerConnection.set("scm:git:https://github.com/navikt/klage-auth.git")
                    url.set("https://github.com/navikt/klage-auth")
                }
            }
        }
    }
}

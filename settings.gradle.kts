pluginManagement {
    includeBuild("build-logic")
}

// The root is not published. Its name differs from the modules so that a composite build
// (--include-build) can substitute no.nav.klage:klage-auth unambiguously.
rootProject.name = "klage-auth-build"

include("klage-auth", "klage-auth-test")

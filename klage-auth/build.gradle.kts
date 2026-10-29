plugins {
    id("klage-auth.library-conventions")
}

dependencies {
    api("org.springframework.security:spring-security-oauth2-resource-server")
    api("org.springframework.security:spring-security-oauth2-jose")
    implementation("org.slf4j:slf4j-api")

    testImplementation("org.springframework:spring-test")
    testRuntimeOnly("org.slf4j:slf4j-simple")
}

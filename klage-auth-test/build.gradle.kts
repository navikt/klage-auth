plugins {
    id("klage-auth.spring-test-conventions")
}

val mockOauth2ServerVersion = "6.1.4"

dependencies {
    api(project(":klage-auth"))
    api("no.nav.security:mock-oauth2-server:$mockOauth2ServerVersion")
    api("org.springframework:spring-test")
    api("org.junit.jupiter:junit-jupiter-api")
    implementation("org.springframework:spring-beans")
    compileOnly("jakarta.servlet:jakarta.servlet-api")

    testImplementation("org.springframework.boot:spring-boot-starter-webmvc")
    testImplementation("org.springframework.boot:spring-boot-starter-security-oauth2-resource-server")
    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
}

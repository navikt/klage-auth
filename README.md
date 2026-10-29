# klage-auth

Validerer Azure AD-tokens i Spring Boot-appene til team klage. Erstatter token-validation-spring fra token-support.

## Moduler

- `no.nav.klage:klage-auth` lager en `JwtDecoder` som bare godtar RS256-tokens fra Azure AD der issuer, audience og tidspunkter stemmer. `azp` må være en av appene i `accessPolicy.inbound`. Tokenet må ha `iss`, `sub`, `aud`, `exp`, `nbf`, `iat` og `azp`.
- `no.nav.klage:klage-auth-test` har `MockAzure`, som signerer ekte tokens med mock-oauth2-server, og `AzureSecurityContractTest`, som er sikkerhetstestene alle appene skal bestå.

## Bruk

```kotlin
repositories {
    maven("https://github-package-registry-mirror.gc.nav.no/cached/maven-release")
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-resource-server")
    implementation("no.nav.klage:klage-auth:$klageAuthVersion")
    testImplementation("no.nav.klage:klage-auth-test:$klageAuthVersion")
}
```

Appen eier filterkjeden selv. Biblioteket lager bare decoderen:

```kotlin
@Configuration
@EnableWebSecurity
class SecurityConfiguration {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain =
        http
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeHttpRequests {
                it.requestMatchers("/internal/health/**", "/internal/prometheus").permitAll()
                it.anyRequest().authenticated()
            }.oauth2ResourceServer { it.jwt { } }
            .build()

    @Bean
    fun jwtDecoder(environment: Environment): JwtDecoder = azureJwtDecoder(AzureAuthProperties.from(environment))
}
```

`AzureAuthProperties.from` leser `AZURE_OPENID_CONFIG_ISSUER`, `AZURE_OPENID_CONFIG_JWKS_URI`, `AZURE_APP_CLIENT_ID` og `AZURE_APP_PRE_AUTHORIZED_APPS`. Nais setter dem når `azure.application.enabled` er `true`. Appen starter ikke hvis en av dem mangler.

Ikke bruk `spring.security.oauth2.resourceserver.*` i tillegg. Spring Boot ignorerer de innstillingene når appen har sin egen `JwtDecoder`.

## Claims

`currentAzureToken()` gir tokenet for requesten som pågår, eller `null` utenfor en autentisert request. Funksjonen leser security context fra tråden, så den gir `null` i `@Async`-metoder og på andre tråder.

```kotlin
val token = currentAzureToken()
token?.navIdent      // NAVident, bare i on-behalf-of-tokens
token?.displayName   // name
token?.groups        // groups, tom liste hvis claimen mangler
token?.callingApp    // azp_name, bare til logging
token?.tokenValue    // tokenet selv, til on-behalf-of-kall videre
currentAzureTokenType() // CC, OBO eller UNAUTHENTICATED
```

Funksjonene kaster ikke unntak når en claim mangler. Appen bestemmer selv hva som skal skje da.

## Test

```kotlin
@WebMvcTest(MyController::class)
@Import(SecurityConfiguration::class)
class SecurityTest : AzureSecurityContractTest() {
    @MockitoBean
    private lateinit var myService: MyService

    override fun protectedRequest() = get("/api/something")

    override fun unauthenticatedPaths() = listOf("/internal/health", "/internal/prometheus")
}
```

Bruk `mockAzure.token(claims = mapOf("NAVident" to "Z123456"))` for å lage et on-behalf-of-token i egne tester.

## Release

Hver PR må ha nøyaktig én av merkelappene `patch`, `minor` eller `major`. Når PR-en er merget, tagger workflowen ny versjon og publiserer til GitHub Packages. Workflowen «Prerelease» lager en `rc`-versjon fra en branch.

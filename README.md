# klage-auth

Validerer Azure AD- og TokenX-tokens og henter tokens til utgående kall fra Texas i Spring Boot-appene til team klage. Erstatter token-validation-spring og token-client-spring fra token-support.

## Moduler

- `no.nav.klage:klage-auth` lager en `JwtDecoder` som bare godtar RS256-tokens fra Azure AD der issuer, audience og tidspunkter stemmer. `azp` må være en av appene i `accessPolicy.inbound`. Tokenet må ha `iss`, `sub`, `aud`, `exp`, `nbf`, `iat` og `azp`.
- `no.nav.klage:klage-auth` lager også en `JwtDecoder` for TokenX. Den godtar RS256-tokens der issuer, audience og tidspunkter stemmer, og der innbyggeren har logget inn på høyeste nivå (`acr` er `idporten-loa-high` eller `Level4`). Tokenet må ha `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `pid` og `acr`.
- `no.nav.klage:klage-auth-test` har `MockAzure` og `MockTokenX`, som signerer ekte tokens med mock-oauth2-server, og `AzureSecurityContractTest` og `TokenXSecurityContractTest`, som er sikkerhetstestene appene skal bestå.

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

## TokenX

Apper med endepunkter for innbyggere bruker `tokenXJwtDecoder(TokenXAuthProperties.from(environment))`. Den leser `TOKEN_X_ISSUER`, `TOKEN_X_JWKS_URI` og `TOKEN_X_CLIENT_ID`, som Nais setter når `tokenx.enabled` er `true`. Decoderen sjekker ikke `azp`. TokenX utsteder bare tokens til appen for kallere i `accessPolicy.inbound`.

En app som tar imot både Azure- og TokenX-tokens, lager én filterkjede per tokentype og deler dem på sti. Da kan et TokenX-token aldri brukes mot Azure-endepunktene, eller omvendt. Lag decoderne i kjedene, ikke som `JwtDecoder`-beans, så Spring Boot ikke velger feil:

```kotlin
@Bean
@Order(1)
fun azureFilterChain(http: HttpSecurity, environment: Environment): SecurityFilterChain =
    http
        .securityMatcher("/internal/klanker/**")
        // csrf, session og authorizeHttpRequests som over
        .oauth2ResourceServer { it.jwt { jwt -> jwt.decoder(azureJwtDecoder(AzureAuthProperties.from(environment))) } }
        .build()

@Bean
@Order(2)
fun tokenXFilterChain(http: HttpSecurity, environment: Environment): SecurityFilterChain =
    http
        // csrf, session og authorizeHttpRequests som over
        .oauth2ResourceServer { it.jwt { jwt -> jwt.decoder(tokenXJwtDecoder(TokenXAuthProperties.from(environment))) } }
        .build()
```

`currentTokenXToken()` gir TokenX-tokenet for requesten som pågår, og `pid` gir fødselsnummeret til innbyggeren. Funksjonen gir `null` hvis requesten har et Azure-token.

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

## Utgående kall

`TexasClient` henter tokens fra Texas, sidecaren Nais legger ved appen. Texas cacher tokenene, så hent et token for hvert kall og ikke lagre det selv.

```kotlin
@Bean
fun texasClient(environment: Environment) = TexasClient(TexasProperties.from(environment))
```

```kotlin
texasClient.machineToMachineToken("api://dev-gcp.klage.kabal-file-api/.default")
texasClient.onBehalfOfCurrentUser("api://dev-fss.teamdokumenthandtering.dokarkiv/.default")
```

- `machineToMachineToken` gir et token der appen opptrer på egne vegne.
- `onBehalfOfCurrentUser` veksler tokenet i requesten som pågår. Den feiler hvis requesten ikke har et on-behalf-of-token, så appen faller aldri tilbake til sin egen identitet. Kall den på request-tråden.
- `tokenXExchangeForCurrentUser` veksler TokenX-tokenet i requesten som pågår, for eksempel med target `dev-gcp:klage:klage-lookup`. Den feiler hvis requesten ikke har et TokenX-token. Kall den på request-tråden.
- `onBehalfOfToken(target, userToken, identityProvider)` veksler et token du har fra før.

`TexasProperties.from` leser `NAIS_TOKEN_ENDPOINT` og `NAIS_TOKEN_EXCHANGE_ENDPOINT`. Feil fra Texas gir `TexasException`. Meldingen inneholder aldri tokens.

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

`TokenXSecurityContractTest` brukes på samme måte for TokenX-endepunkter. `mockTokenX.token(pid = "12345678910")` lager et gyldig token for en innbygger.

## Release

Hver PR må ha nøyaktig én av merkelappene `patch`, `minor` eller `major`. Når PR-en er merget, tagger workflowen ny versjon og publiserer til GitHub Packages. Workflowen «Prerelease» lager en `rc`-versjon fra en branch.

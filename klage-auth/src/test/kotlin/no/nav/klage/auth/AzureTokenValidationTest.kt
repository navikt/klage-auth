package no.nav.klage.auth

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.springframework.mock.env.MockEnvironment
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimNames
import java.time.Instant

class AzureTokenValidationTest {
    companion object {
        private const val ISSUER = "https://login.microsoftonline.com/tenant/v2.0"
        private const val AUDIENCE = "app-client-id"
        private const val CALLER = "caller-client-id"
    }

    private val validator = azureTokenValidator(issuer = ISSUER, audience = AUDIENCE, preAuthorizedClientIds = setOf(CALLER))

    private fun jwt(modify: MutableMap<String, Any>.() -> Unit = {}): Jwt {
        val now = Instant.now()
        val claims =
            mutableMapOf<String, Any>(
                JwtClaimNames.ISS to ISSUER,
                JwtClaimNames.SUB to "subject",
                JwtClaimNames.AUD to listOf(AUDIENCE),
                JwtClaimNames.EXP to now.plusSeconds(3600),
                JwtClaimNames.NBF to now.minusSeconds(10),
                JwtClaimNames.IAT to now.minusSeconds(10),
                AZP_CLAIM to CALLER,
            ).apply(modify)
        return Jwt
            .withTokenValue("token")
            .header("alg", "RS256")
            .claims { it.putAll(claims) }
            .build()
    }

    @Test
    fun `accepts a valid token`() {
        assertThat(validator.validate(jwt()).hasErrors()).isFalse()
    }

    @Test
    fun `rejects wrong issuer`() {
        assertThat(validator.validate(jwt { put(key = JwtClaimNames.ISS, value = "https://evil.example") }).hasErrors()).isTrue()
    }

    @Test
    fun `rejects wrong audience`() {
        assertThat(validator.validate(jwt { put(key = JwtClaimNames.AUD, value = listOf("other-app")) }).hasErrors()).isTrue()
    }

    @Test
    fun `rejects expired token`() {
        val expired =
            jwt {
                put(key = JwtClaimNames.IAT, value = Instant.now().minusSeconds(3600))
                put(key = JwtClaimNames.NBF, value = Instant.now().minusSeconds(3600))
                put(key = JwtClaimNames.EXP, value = Instant.now().minusSeconds(300))
            }
        assertThat(validator.validate(expired).hasErrors()).isTrue()
    }

    @Test
    fun `rejects token from a caller that is not pre-authorized`() {
        assertThat(validator.validate(jwt { put(key = AZP_CLAIM, value = "unknown-client") }).hasErrors()).isTrue()
    }

    @Test
    fun `rejects token missing any required claim`() {
        AZURE_REQUIRED_CLAIMS.forEach { claim ->
            assertThat(validator.validate(jwt { remove(claim) }).hasErrors())
                .describedAs("token without $claim")
                .isTrue()
        }
    }

    @Test
    fun `refuses to validate against an empty allow list`() {
        assertThatThrownBy { AzpValidator(emptySet()) }.isInstanceOf(IllegalArgumentException::class.java)
    }

    @Test
    fun `parses client ids from AZURE_APP_PRE_AUTHORIZED_APPS`() {
        val json =
            """[{"name":"dev-gcp:klage:kabal-api","clientId":"a"},{"name":"dev-gcp:klage:kabin-api","clientId":"b"}]"""
        assertThat(parsePreAuthorizedClientIds(json)).containsExactlyInAnyOrder("a", "b")
    }

    @Test
    fun `fails on missing or malformed AZURE_APP_PRE_AUTHORIZED_APPS`() {
        listOf("", "  ", "[]", "not json", """{"clientId":"a"}""", """[{"name":"x"}]""", """[{"clientId":""}]""")
            .forEach { json ->
                assertThatThrownBy { parsePreAuthorizedClientIds(json) }
                    .describedAs("input '$json'")
                    .isInstanceOf(IllegalStateException::class.java)
            }
    }

    @Test
    fun `reads properties from the Nais environment variables`() {
        val environment =
            MockEnvironment()
                .withProperty(AzureAuthProperties.ISSUER, ISSUER)
                .withProperty(AzureAuthProperties.JWKS_URI, "https://example/keys")
                .withProperty(AzureAuthProperties.CLIENT_ID, AUDIENCE)
                .withProperty(AzureAuthProperties.PRE_AUTHORIZED_APPS, """[{"name":"x","clientId":"$CALLER"}]""")

        assertThat(AzureAuthProperties.from(environment)).isEqualTo(
            AzureAuthProperties(
                issuer = ISSUER,
                jwksUri = "https://example/keys",
                clientId = AUDIENCE,
                preAuthorizedClientIds = setOf(CALLER),
            ),
        )
    }

    @Test
    fun `fails when a Nais environment variable is missing`() {
        val environment = MockEnvironment().withProperty(AzureAuthProperties.ISSUER, ISSUER)
        assertThatThrownBy { AzureAuthProperties.from(environment) }.isInstanceOf(IllegalStateException::class.java)
    }
}

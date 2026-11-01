package no.nav.klage.auth

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.springframework.mock.env.MockEnvironment
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimNames
import java.time.Instant

class TokenXTokenValidationTest {
    companion object {
        private const val ISSUER = "https://tokenx.dev-gcp.nav.cloud.nais.io"
        private const val AUDIENCE = "dev-gcp:klage:klage-dittnav-api"
    }

    private val validator = tokenXTokenValidator(issuer = ISSUER, audience = AUDIENCE)

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
                TokenXClaimNames.PID to "12345678910",
                TokenXClaimNames.ACR to "idporten-loa-high",
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
    fun `accepts both formats of the highest login level`() {
        ACR_HIGH.forEach { acr ->
            assertThat(validator.validate(jwt { put(key = TokenXClaimNames.ACR, value = acr) }).hasErrors())
                .describedAs("acr $acr")
                .isFalse()
        }
    }

    @Test
    fun `rejects a lower login level`() {
        listOf("idporten-loa-substantial", "Level3", "level4", "").forEach { acr ->
            assertThat(validator.validate(jwt { put(key = TokenXClaimNames.ACR, value = acr) }).hasErrors())
                .describedAs("acr '$acr'")
                .isTrue()
        }
    }

    @Test
    fun `accepts the login levels the app asks for`() {
        val substantial = tokenXTokenValidator(issuer = ISSUER, audience = AUDIENCE, acceptedAcrValues = setOf("idporten-loa-substantial"))

        assertThat(substantial.validate(jwt { put(key = TokenXClaimNames.ACR, value = "idporten-loa-substantial") }).hasErrors()).isFalse()
        assertThat(substantial.validate(jwt()).hasErrors()).isTrue()
    }

    @Test
    fun `rejects wrong issuer`() {
        assertThat(validator.validate(jwt { put(key = JwtClaimNames.ISS, value = "https://evil.example") }).hasErrors()).isTrue()
    }

    @Test
    fun `rejects wrong audience`() {
        assertThat(validator.validate(jwt { put(key = JwtClaimNames.AUD, value = listOf("dev-gcp:klage:other-app")) }).hasErrors()).isTrue()
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
    fun `rejects token missing any required claim`() {
        TOKENX_REQUIRED_CLAIMS.forEach { claim ->
            assertThat(validator.validate(jwt { remove(claim) }).hasErrors())
                .describedAs("token without $claim")
                .isTrue()
        }
    }

    @Test
    fun `refuses to validate against no accepted login levels`() {
        assertThatThrownBy { AcrValidator(emptySet()) }.isInstanceOf(IllegalArgumentException::class.java)
    }

    @Test
    fun `reads properties from the Nais environment variables`() {
        val environment =
            MockEnvironment()
                .withProperty(TokenXAuthProperties.ISSUER, ISSUER)
                .withProperty(TokenXAuthProperties.JWKS_URI, "https://example/jwks")
                .withProperty(TokenXAuthProperties.CLIENT_ID, AUDIENCE)

        assertThat(TokenXAuthProperties.from(environment))
            .isEqualTo(TokenXAuthProperties(issuer = ISSUER, jwksUri = "https://example/jwks", clientId = AUDIENCE))
    }

    @Test
    fun `fails when a Nais environment variable is missing`() {
        val environment = MockEnvironment().withProperty(TokenXAuthProperties.ISSUER, ISSUER)
        assertThatThrownBy { TokenXAuthProperties.from(environment) }.isInstanceOf(IllegalStateException::class.java)
    }
}

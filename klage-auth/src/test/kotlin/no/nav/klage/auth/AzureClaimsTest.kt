package no.nav.klage.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken

class AzureClaimsTest {
    private fun jwt(vararg claims: Pair<String, Any>): Jwt =
        Jwt
            .withTokenValue("encoded-token")
            .header("alg", "RS256")
            .claim("sub", "subject")
            .claims { it.putAll(claims) }
            .build()

    private val oboToken =
        jwt(
            AzureClaimNames.NAV_IDENT to "Z123456",
            AzureClaimNames.NAME to "Saksbehandler Saksbehandlersen",
            AzureClaimNames.GROUPS to listOf("group-a", "group-b"),
            AzureClaimNames.AZP_NAME to "dev-gcp:klage:kabal-frontend",
        )

    private val ccToken =
        jwt(
            AzureClaimNames.IDTYP to "app",
            AzureClaimNames.AZP_NAME to "dev-gcp:klage:kabal-api",
        )

    @AfterEach
    fun clearContext() {
        SecurityContextHolder.clearContext()
    }

    @Test
    fun `reads claims from on-behalf-of token`() {
        assertThat(oboToken.navIdent).isEqualTo("Z123456")
        assertThat(oboToken.displayName).isEqualTo("Saksbehandler Saksbehandlersen")
        assertThat(oboToken.groups).containsExactly("group-a", "group-b")
        assertThat(oboToken.callingApp).isEqualTo("dev-gcp:klage:kabal-frontend")
        assertThat(oboToken.tokenType).isEqualTo(AzureTokenType.OBO)
    }

    @Test
    fun `client credentials token has no user claims`() {
        assertThat(ccToken.navIdent).isNull()
        assertThat(ccToken.displayName).isNull()
        assertThat(ccToken.groups).isEmpty()
        assertThat(ccToken.callingApp).isEqualTo("dev-gcp:klage:kabal-api")
        assertThat(ccToken.tokenType).isEqualTo(AzureTokenType.CC)
    }

    @Test
    fun `token with neither idtyp app nor NAVident is unauthenticated`() {
        assertThat(jwt().tokenType).isEqualTo(AzureTokenType.UNAUTHENTICATED)
    }

    @Test
    fun `reads token from security context`() {
        SecurityContextHolder.getContext().authentication = JwtAuthenticationToken(oboToken)

        assertThat(currentAzureToken()?.tokenValue).isEqualTo("encoded-token")
        assertThat(currentAzureToken()?.navIdent).isEqualTo("Z123456")
        assertThat(currentAzureTokenType()).isEqualTo(AzureTokenType.OBO)
    }

    @Test
    fun `no token outside an authenticated request`() {
        assertThat(currentAzureToken()).isNull()
        assertThat(currentAzureTokenType()).isEqualTo(AzureTokenType.UNAUTHENTICATED)
    }

    @Test
    fun `no token when authenticated by something other than a JWT`() {
        SecurityContextHolder.getContext().authentication = TestingAuthenticationToken("user", "password")

        assertThat(currentAzureToken()).isNull()
    }
}

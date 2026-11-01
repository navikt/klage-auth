package no.nav.klage.auth

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken

class TokenXClaimsTest {
    private fun jwt(vararg claims: Pair<String, Any>): Jwt =
        Jwt
            .withTokenValue("encoded-token")
            .header("alg", "RS256")
            .claim("sub", "subject")
            .claims { it.putAll(claims) }
            .build()

    @AfterEach
    fun clearContext() {
        SecurityContextHolder.clearContext()
    }

    @Test
    fun `reads pid from token in security context`() {
        SecurityContextHolder.getContext().authentication = JwtAuthenticationToken(jwt(TokenXClaimNames.PID to "12345678910"))

        assertThat(currentTokenXToken()?.pid).isEqualTo("12345678910")
        assertThat(currentTokenXToken()?.tokenValue).isEqualTo("encoded-token")
    }

    @Test
    fun `an Azure token is not a TokenX token`() {
        SecurityContextHolder.getContext().authentication = JwtAuthenticationToken(jwt(AzureClaimNames.IDTYP to "app"))

        assertThat(currentTokenXToken()).isNull()
    }

    @Test
    fun `no token outside an authenticated request`() {
        assertThat(currentTokenXToken()).isNull()
    }
}

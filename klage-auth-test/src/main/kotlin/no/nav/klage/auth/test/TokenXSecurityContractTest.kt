package no.nav.klage.auth.test

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpHeaders
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

/**
 * The security tests every app with TokenX endpoints should pass. Use it like
 * [AzureSecurityContractTest], with a request to an endpoint that requires a TokenX token.
 */
public abstract class TokenXSecurityContractTest {
    public companion object {
        @JvmStatic
        public val mockTokenX: MockTokenX = MockTokenX()

        @JvmStatic
        @DynamicPropertySource
        public fun tokenXProperties(registry: DynamicPropertyRegistry) {
            mockTokenX.registerProperties(registry)
        }

        private const val UNAUTHORIZED = 401
        private const val FORBIDDEN = 403
    }

    @Autowired
    protected lateinit var mockMvc: MockMvc

    /** A request to an endpoint that requires a TokenX token. */
    protected abstract fun protectedRequest(): MockHttpServletRequestBuilder

    /** What a valid token should give on [protectedRequest]. Defaults to any 2xx. */
    protected open fun assertAccepted(result: ResultActions) {
        result.andExpect(status().is2xxSuccessful)
    }

    /** Paths the Nais probes and Prometheus must reach without a token. */
    protected open fun unauthenticatedPaths(): List<String> = listOf("/internal/health")

    @Test
    public fun `accepts valid token`() {
        assertAccepted(perform(mockTokenX.token()))
    }

    @Test
    public fun `rejects request without token`() {
        perform(token = null).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `rejects token with wrong audience`() {
        perform(mockTokenX.token(audience = "dev-gcp:klage:other-app")).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `rejects token from another issuer`() {
        perform(mockTokenX.tokenFromOtherIssuer()).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `rejects expired token`() {
        perform(mockTokenX.token(expirySeconds = -300)).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `rejects token with lower login level`() {
        perform(mockTokenX.token(acr = "idporten-loa-substantial")).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `rejects token without pid`() {
        perform(mockTokenX.token(pid = null)).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `rejects HS256 token`() {
        perform(mockTokenX.hs256Token()).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `rejects unsigned token`() {
        perform(mockTokenX.unsignedToken()).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `unauthenticated paths are reachable without token`() {
        unauthenticatedPaths().forEach { path ->
            val status =
                mockMvc
                    .perform(get(path))
                    .andReturn()
                    .response.status
            assertFalse(status == UNAUTHORIZED || status == FORBIDDEN, "$path returned $status")
        }
    }

    private fun perform(token: String?): ResultActions =
        mockMvc.perform(
            protectedRequest().apply {
                if (token != null) header(HttpHeaders.AUTHORIZATION, "Bearer $token")
            },
        )
}

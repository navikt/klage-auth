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
 * The security tests every app should pass. Extend it from a `@WebMvcTest` (or `@SpringBootTest`
 * with `@AutoConfigureMockMvc`) that loads the app's security configuration:
 *
 * ```
 * @WebMvcTest(MyController::class)
 * @Import(SecurityConfiguration::class)
 * class SecurityTest : AzureSecurityContractTest() {
 *     override fun protectedRequest() = get("/api/something")
 * }
 * ```
 */
public abstract class AzureSecurityContractTest {
    public companion object {
        @JvmStatic
        public val mockAzure: MockAzure = MockAzure()

        @JvmStatic
        @DynamicPropertySource
        public fun azureProperties(registry: DynamicPropertyRegistry) {
            mockAzure.registerProperties(registry)
        }

        private const val UNAUTHORIZED = 401
        private const val FORBIDDEN = 403
    }

    @Autowired
    protected lateinit var mockMvc: MockMvc

    /** A request to an endpoint that requires a token. */
    protected abstract fun protectedRequest(): MockHttpServletRequestBuilder

    /** What a valid token should give on [protectedRequest]. Defaults to any 2xx. */
    protected open fun assertAccepted(result: ResultActions) {
        result.andExpect(status().is2xxSuccessful)
    }

    /** Paths the Nais probes and Prometheus must reach without a token. */
    protected open fun unauthenticatedPaths(): List<String> = listOf("/internal/health")

    @Test
    public fun `accepts valid token from pre-authorized caller`() {
        assertAccepted(perform(mockAzure.token()))
    }

    @Test
    public fun `rejects request without token`() {
        perform(token = null).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `rejects token with wrong audience`() {
        perform(mockAzure.token(audience = "other-app")).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `rejects token from another issuer`() {
        perform(mockAzure.tokenFromOtherIssuer()).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `rejects expired token`() {
        perform(mockAzure.token(expirySeconds = -300)).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `rejects token from caller that is not pre-authorized`() {
        perform(mockAzure.token(azp = "unknown-client")).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `rejects HS256 token`() {
        perform(mockAzure.hs256Token()).andExpect(status().isUnauthorized)
    }

    @Test
    public fun `rejects unsigned token`() {
        perform(mockAzure.unsignedToken()).andExpect(status().isUnauthorized)
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

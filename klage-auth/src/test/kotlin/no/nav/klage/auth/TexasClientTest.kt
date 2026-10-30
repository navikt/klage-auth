package no.nav.klage.auth

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.mock.env.MockEnvironment
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.test.web.client.MockRestServiceServer
import org.springframework.test.web.client.match.MockRestRequestMatchers.content
import org.springframework.test.web.client.match.MockRestRequestMatchers.method
import org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo
import org.springframework.test.web.client.response.MockRestResponseCreators.withStatus
import org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.client.RestClient

class TexasClientTest {
    private companion object {
        const val TOKEN_ENDPOINT = "http://texas/api/v1/token"
        const val EXCHANGE_ENDPOINT = "http://texas/api/v1/token/exchange"
        const val TARGET = "api://dev-gcp.klage.kabal-file-api/.default"
        const val TOKEN_RESPONSE = """{"access_token":"outgoing-token","token_type":"Bearer","expires_in":3599}"""
    }

    private val restClientBuilder = RestClient.builder()
    private val server = MockRestServiceServer.bindTo(restClientBuilder).build()
    private val client =
        TexasClient(
            properties = TexasProperties(tokenEndpoint = TOKEN_ENDPOINT, tokenExchangeEndpoint = EXCHANGE_ENDPOINT),
            restClient = restClientBuilder.build(),
        )

    @AfterEach
    fun tearDown() {
        SecurityContextHolder.clearContext()
    }

    private fun form(vararg fields: Pair<String, String>) =
        LinkedMultiValueMap<String, String>().apply { fields.forEach { (key, value) -> add(key, value) } }

    private fun expectTokenRequest(
        endpoint: String,
        vararg fields: Pair<String, String>,
    ) {
        server
            .expect(requestTo(endpoint))
            .andExpect(method(HttpMethod.POST))
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_FORM_URLENCODED))
            .andExpect(content().formData(form(*fields)))
            .andRespond(withSuccess(TOKEN_RESPONSE, MediaType.APPLICATION_JSON))
    }

    private fun authenticate(vararg claims: Pair<String, Any>) {
        val jwt =
            Jwt
                .withTokenValue("incoming-token")
                .header("alg", "RS256")
                .claim("sub", "subject")
                .claims { it.putAll(claims) }
                .build()
        SecurityContextHolder.getContext().authentication = JwtAuthenticationToken(jwt)
    }

    @Test
    fun `machine-to-machine token`() {
        expectTokenRequest(TOKEN_ENDPOINT, "identity_provider" to "entra_id", "target" to TARGET)

        assertThat(client.machineToMachineToken(TARGET)).isEqualTo("outgoing-token")
        server.verify()
    }

    @Test
    fun `on-behalf-of token`() {
        expectTokenRequest(
            EXCHANGE_ENDPOINT,
            "identity_provider" to "entra_id",
            "target" to TARGET,
            "user_token" to "incoming-token",
        )

        assertThat(client.onBehalfOfToken(target = TARGET, userToken = "incoming-token")).isEqualTo("outgoing-token")
        server.verify()
    }

    @Test
    fun `on-behalf-of current user exchanges the token of the request`() {
        authenticate(AzureClaimNames.NAV_IDENT to "Z123456")
        expectTokenRequest(
            EXCHANGE_ENDPOINT,
            "identity_provider" to "entra_id",
            "target" to TARGET,
            "user_token" to "incoming-token",
        )

        assertThat(client.onBehalfOfCurrentUser(TARGET)).isEqualTo("outgoing-token")
        server.verify()
    }

    @Test
    fun `on-behalf-of current user fails for a machine-to-machine token`() {
        authenticate(AzureClaimNames.IDTYP to "app")

        assertThatThrownBy { client.onBehalfOfCurrentUser(TARGET) }
            .isInstanceOf(TexasException::class.java)
            .hasMessageContaining("CC")
        server.verify()
    }

    @Test
    fun `on-behalf-of current user fails outside an authenticated request`() {
        assertThatThrownBy { client.onBehalfOfCurrentUser(TARGET) }.isInstanceOf(TexasException::class.java)
        server.verify()
    }

    @Test
    fun `on-behalf-of rejects a blank user token`() {
        assertThatThrownBy { client.onBehalfOfToken(target = TARGET, userToken = " ") }
            .isInstanceOf(IllegalArgumentException::class.java)
    }

    @Test
    fun `error from Texas becomes TexasException without the user token`() {
        server
            .expect(requestTo(EXCHANGE_ENDPOINT))
            .andRespond(
                withStatus(HttpStatus.BAD_REQUEST)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("""{"error":"invalid_grant","error_description":"AADSTS50013"}"""),
            )

        assertThatThrownBy { client.onBehalfOfToken(target = TARGET, userToken = "incoming-token") }
            .isInstanceOf(TexasException::class.java)
            .hasMessageContaining("400")
            .hasMessageContaining("invalid_grant")
            .hasMessageNotContaining("incoming-token")
    }

    @Test
    fun `response without access_token fails`() {
        server
            .expect(requestTo(TOKEN_ENDPOINT))
            .andRespond(withSuccess("""{"token_type":"Bearer","expires_in":3599}""", MediaType.APPLICATION_JSON))

        assertThatThrownBy { client.machineToMachineToken(TARGET) }.isInstanceOf(TexasException::class.java)
    }

    @Test
    fun `properties are read from the Nais variables`() {
        val environment =
            MockEnvironment()
                .withProperty(TexasProperties.TOKEN_ENDPOINT, TOKEN_ENDPOINT)
                .withProperty(TexasProperties.TOKEN_EXCHANGE_ENDPOINT, EXCHANGE_ENDPOINT)

        assertThat(TexasProperties.from(environment))
            .isEqualTo(TexasProperties(tokenEndpoint = TOKEN_ENDPOINT, tokenExchangeEndpoint = EXCHANGE_ENDPOINT))
    }

    @Test
    fun `missing Nais variable fails at startup`() {
        assertThatThrownBy { TexasProperties.from(MockEnvironment()) }
            .isInstanceOf(IllegalStateException::class.java)
    }
}

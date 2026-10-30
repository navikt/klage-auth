package no.nav.klage.auth

import org.springframework.core.env.Environment
import org.springframework.http.MediaType
import org.springframework.http.client.JdkClientHttpRequestFactory
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestClientException
import org.springframework.web.client.RestClientResponseException
import org.springframework.web.client.support.RestClientAdapter
import org.springframework.web.service.annotation.PostExchange
import org.springframework.web.service.invoker.HttpServiceProxyFactory
import org.springframework.web.service.invoker.createClient
import java.net.URI
import java.net.http.HttpClient
import java.time.Duration

/**
 * The Texas endpoints Nais injects when an identity provider such as `azure.application.enabled` is on.
 */
public data class TexasProperties(
    val tokenEndpoint: String,
    val tokenExchangeEndpoint: String,
) {
    public companion object {
        public const val TOKEN_ENDPOINT: String = "NAIS_TOKEN_ENDPOINT"
        public const val TOKEN_EXCHANGE_ENDPOINT: String = "NAIS_TOKEN_EXCHANGE_ENDPOINT"

        /** Fails if any of the variables is missing, so a misconfigured app does not start. */
        public fun from(environment: Environment): TexasProperties =
            TexasProperties(
                tokenEndpoint = environment.getRequiredProperty(TOKEN_ENDPOINT),
                tokenExchangeEndpoint = environment.getRequiredProperty(TOKEN_EXCHANGE_ENDPOINT),
            )
    }
}

public enum class TexasIdentityProvider(
    public val value: String,
) {
    ENTRA_ID("entra_id"),
    TOKENX("tokenx"),
}

/**
 * Thrown when Texas does not return a token. The message never contains a token.
 */
public class TexasException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/**
 * The Texas API. The endpoints come from Nais as full URLs, so each call takes its [URI].
 * `@RequestParam` with form content type puts the parameters in the request body.
 */
internal interface TexasApi {
    @PostExchange(contentType = MediaType.APPLICATION_FORM_URLENCODED_VALUE, accept = [MediaType.APPLICATION_JSON_VALUE])
    fun token(
        endpoint: URI,
        @RequestParam("identity_provider") identityProvider: String,
        @RequestParam("target") target: String,
    ): Map<String, Any?>?

    @PostExchange(contentType = MediaType.APPLICATION_FORM_URLENCODED_VALUE, accept = [MediaType.APPLICATION_JSON_VALUE])
    fun exchange(
        endpoint: URI,
        @RequestParam("identity_provider") identityProvider: String,
        @RequestParam("target") target: String,
        @RequestParam("user_token") userToken: String,
    ): Map<String, Any?>?
}

/**
 * Gets tokens for outgoing calls from Texas, the Nais sidecar. Texas caches the tokens until shortly
 * before they expire, so call this for every outgoing request instead of storing the token.
 *
 * `target` is the scope of the receiving app, for example `api://dev-gcp.klage.kabal-file-api/.default`.
 */
public class TexasClient(
    properties: TexasProperties,
    restClient: RestClient = defaultRestClient(),
) {
    private companion object {
        private val CONNECT_TIMEOUT: Duration = Duration.ofSeconds(2)
        private val READ_TIMEOUT: Duration = Duration.ofSeconds(10)
        private const val MAX_ERROR_BODY_LENGTH = 1024

        private fun defaultRestClient(): RestClient =
            RestClient
                .builder()
                .requestFactory(
                    JdkClientHttpRequestFactory(HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build())
                        .apply { setReadTimeout(READ_TIMEOUT) },
                ).build()
    }

    private val texasApi: TexasApi =
        HttpServiceProxyFactory
            .builder()
            .exchangeAdapter(RestClientAdapter.create(restClient))
            .build()
            .createClient<TexasApi>()

    private val tokenEndpoint = URI.create(properties.tokenEndpoint)
    private val tokenExchangeEndpoint = URI.create(properties.tokenExchangeEndpoint)

    /** A token where the app acts on its own behalf (client credentials). */
    public fun machineToMachineToken(
        target: String,
        identityProvider: TexasIdentityProvider = TexasIdentityProvider.ENTRA_ID,
    ): String =
        requestToken(target) {
            texasApi.token(endpoint = tokenEndpoint, identityProvider = identityProvider.value, target = target)
        }

    /**
     * Exchanges the user's token for a token to [target] (on-behalf-of for Entra ID, token exchange for TokenX).
     */
    public fun onBehalfOfToken(
        target: String,
        userToken: String,
        identityProvider: TexasIdentityProvider = TexasIdentityProvider.ENTRA_ID,
    ): String {
        require(userToken.isNotBlank()) { "userToken is blank." }
        return requestToken(target) {
            texasApi.exchange(
                endpoint = tokenExchangeEndpoint,
                identityProvider = identityProvider.value,
                target = target,
                userToken = userToken,
            )
        }
    }

    /**
     * Exchanges the Entra ID token of the current request. Fails unless the request carries an
     * on-behalf-of token, so a call never falls back to the app's own identity.
     *
     * Reads the thread bound security context, so call it on the request thread, not in `@Async` code.
     */
    public fun onBehalfOfCurrentUser(target: String): String {
        val token = currentAzureToken() ?: throw TexasException("No authenticated request to exchange a token for.")
        if (token.tokenType != AzureTokenType.OBO) {
            throw TexasException("The current request has a ${token.tokenType} token, an on-behalf-of token is required.")
        }
        return onBehalfOfToken(target = target, userToken = token.tokenValue)
    }

    private fun requestToken(
        target: String,
        call: () -> Map<String, Any?>?,
    ): String {
        val response =
            try {
                call()
            } catch (e: RestClientResponseException) {
                // The error body is an RFC 6749 error from Texas or the identity provider, never a token.
                val error = e.responseBodyAsString.take(MAX_ERROR_BODY_LENGTH)
                throw TexasException(
                    message = "Texas returned ${e.statusCode.value()} for target '$target': $error",
                    cause = e,
                )
            } catch (e: RestClientException) {
                throw TexasException(message = "Could not get a token from Texas for target '$target'.", cause = e)
            }
        val accessToken = response?.get("access_token") as? String
        if (accessToken.isNullOrBlank()) {
            throw TexasException("Texas returned no access_token for target '$target'.")
        }
        return accessToken
    }
}

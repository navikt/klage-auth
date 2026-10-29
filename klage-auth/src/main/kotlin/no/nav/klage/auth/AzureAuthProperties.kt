package no.nav.klage.auth

import com.nimbusds.jose.util.JSONArrayUtils
import org.springframework.core.env.Environment
import java.text.ParseException

/**
 * The Azure AD settings Nais injects when `azure.application.enabled` is true.
 */
public data class AzureAuthProperties(
    val issuer: String,
    val jwksUri: String,
    val clientId: String,
    val preAuthorizedClientIds: Set<String>,
) {
    public companion object {
        public const val ISSUER: String = "AZURE_OPENID_CONFIG_ISSUER"
        public const val JWKS_URI: String = "AZURE_OPENID_CONFIG_JWKS_URI"
        public const val CLIENT_ID: String = "AZURE_APP_CLIENT_ID"
        public const val PRE_AUTHORIZED_APPS: String = "AZURE_APP_PRE_AUTHORIZED_APPS"

        /**
         * Reads the Nais variables directly, so apps need no yaml for token validation.
         * Fails if any of them is missing, so a misconfigured app does not start.
         */
        public fun from(environment: Environment): AzureAuthProperties =
            AzureAuthProperties(
                issuer = environment.getRequiredProperty(ISSUER),
                jwksUri = environment.getRequiredProperty(JWKS_URI),
                clientId = environment.getRequiredProperty(CLIENT_ID),
                preAuthorizedClientIds = parsePreAuthorizedClientIds(environment.getRequiredProperty(PRE_AUTHORIZED_APPS)),
            )
    }
}

/**
 * Parses AZURE_APP_PRE_AUTHORIZED_APPS, a JSON array of {"name": ..., "clientId": ...}.
 * Fails on anything unexpected instead of accepting the wrong callers.
 */
public fun parsePreAuthorizedClientIds(json: String): Set<String> {
    check(json.isNotBlank()) { "${AzureAuthProperties.PRE_AUTHORIZED_APPS} is empty." }
    val apps =
        try {
            JSONArrayUtils.parse(json)
        } catch (e: ParseException) {
            throw IllegalStateException("${AzureAuthProperties.PRE_AUTHORIZED_APPS} is not a JSON array.", e)
        }
    val clientIds =
        apps
            .map { app ->
                val clientId = (app as? Map<*, *>)?.get("clientId") as? String
                check(!clientId.isNullOrBlank()) { "${AzureAuthProperties.PRE_AUTHORIZED_APPS} has an entry without clientId." }
                clientId
            }.toSet()
    check(clientIds.isNotEmpty()) { "${AzureAuthProperties.PRE_AUTHORIZED_APPS} contains no apps." }
    return clientIds
}

package no.nav.klage.auth

import org.springframework.core.env.Environment

/**
 * The TokenX settings Nais injects when `tokenx.enabled` is true.
 */
public data class TokenXAuthProperties(
    val issuer: String,
    val jwksUri: String,
    val clientId: String,
) {
    public companion object {
        public const val ISSUER: String = "TOKEN_X_ISSUER"
        public const val JWKS_URI: String = "TOKEN_X_JWKS_URI"
        public const val CLIENT_ID: String = "TOKEN_X_CLIENT_ID"

        /** Fails if any of the variables is missing, so a misconfigured app does not start. */
        public fun from(environment: Environment): TokenXAuthProperties =
            TokenXAuthProperties(
                issuer = environment.getRequiredProperty(ISSUER),
                jwksUri = environment.getRequiredProperty(JWKS_URI),
                clientId = environment.getRequiredProperty(CLIENT_ID),
            )
    }
}

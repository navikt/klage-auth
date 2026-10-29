package no.nav.klage.auth

import org.slf4j.LoggerFactory
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder

public const val AZP_CLAIM: String = "azp"

/**
 * The claims token-support required by default, plus azp. Spring only validates claims that are
 * present, so a token without exp would otherwise be accepted.
 */
public val AZURE_REQUIRED_CLAIMS: Set<String> =
    setOf(
        JwtClaimNames.ISS,
        JwtClaimNames.SUB,
        JwtClaimNames.AUD,
        JwtClaimNames.EXP,
        JwtClaimNames.NBF,
        JwtClaimNames.IAT,
        AZP_CLAIM,
    )

/**
 * Decoder for Azure AD tokens: RS256 only, keys from the JWKS endpoint, and every check in
 * [azureTokenValidator].
 *
 * Registering this as a bean disables Spring Boot's resource server auto-configuration, including
 * its audience check, so do not combine it with `spring.security.oauth2.resourceserver.*`.
 */
public fun azureJwtDecoder(properties: AzureAuthProperties): JwtDecoder =
    NimbusJwtDecoder
        .withJwkSetUri(properties.jwksUri)
        .jwsAlgorithm(SignatureAlgorithm.RS256)
        .build()
        .apply {
            setJwtValidator(
                azureTokenValidator(
                    issuer = properties.issuer,
                    audience = properties.clientId,
                    preAuthorizedClientIds = properties.preAuthorizedClientIds,
                ),
            )
        }

/**
 * Everything a token must satisfy after its signature has been verified.
 */
public fun azureTokenValidator(
    issuer: String,
    audience: String,
    preAuthorizedClientIds: Set<String>,
): OAuth2TokenValidator<Jwt> =
    DelegatingOAuth2TokenValidator(
        JwtValidators.createDefaultWithIssuer(issuer),
        RequiredClaimsValidator(AZURE_REQUIRED_CLAIMS),
        OAuth2TokenValidator { jwt ->
            if (jwt.audience.orEmpty().contains(audience)) {
                OAuth2TokenValidatorResult.success()
            } else {
                OAuth2TokenValidatorResult.failure(invalidToken("The aud claim does not contain this app."))
            }
        },
        AzpValidator(preAuthorizedClientIds),
    )

public class RequiredClaimsValidator(
    private val requiredClaims: Set<String>,
) : OAuth2TokenValidator<Jwt> {
    override fun validate(token: Jwt): OAuth2TokenValidatorResult {
        val missing = requiredClaims.filterNot { token.hasClaim(it) }
        return if (missing.isEmpty()) {
            OAuth2TokenValidatorResult.success()
        } else {
            OAuth2TokenValidatorResult.failure(invalidToken("Missing required claims: $missing"))
        }
    }
}

/**
 * Only accepts tokens issued to apps that Nais has pre-authorized through accessPolicy.inbound.
 */
public class AzpValidator(
    private val preAuthorizedClientIds: Set<String>,
) : OAuth2TokenValidator<Jwt> {
    private companion object {
        private val logger = LoggerFactory.getLogger(AzpValidator::class.java)

        private const val MAX_LOGGED_LENGTH = 64
        private val UNSAFE_LOG_CHARACTERS = Regex("[^A-Za-z0-9-]")
    }

    init {
        require(preAuthorizedClientIds.isNotEmpty()) { "No pre-authorized client ids configured." }
    }

    override fun validate(token: Jwt): OAuth2TokenValidatorResult {
        val azp = token.getClaimAsString(AZP_CLAIM)
        if (azp != null && azp in preAuthorizedClientIds) {
            return OAuth2TokenValidatorResult.success()
        }
        logger.warn("Rejected token with azp '{}', not a pre-authorized client.", azp?.toLoggable())
        return OAuth2TokenValidatorResult.failure(invalidToken("The azp claim is not a pre-authorized client."))
    }

    // azp comes from a token that has not been accepted, so it is untrusted input.
    private fun String.toLoggable(): String = take(MAX_LOGGED_LENGTH).replace(regex = UNSAFE_LOG_CHARACTERS, replacement = "?")
}

private fun invalidToken(description: String) = OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, description, null)

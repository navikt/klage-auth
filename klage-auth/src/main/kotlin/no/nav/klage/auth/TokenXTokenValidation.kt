package no.nav.klage.auth

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder

public object TokenXClaimNames {
    public const val PID: String = "pid"
    public const val ACR: String = "acr"
}

/**
 * The highest ID-porten level, in both formats. ID-porten returns the format the login asked for,
 * so the frontend decides which one the token gets. The two values mean the same level.
 */
public val ACR_HIGH: Set<String> = setOf("idporten-loa-high", "Level4")

/**
 * The claims token-support required by default, plus pid (the citizen) and acr (the login level).
 * No azp check: TokenX only issues a token for this app to callers in `accessPolicy.inbound`.
 */
public val TOKENX_REQUIRED_CLAIMS: Set<String> =
    setOf(
        JwtClaimNames.ISS,
        JwtClaimNames.SUB,
        JwtClaimNames.AUD,
        JwtClaimNames.EXP,
        JwtClaimNames.NBF,
        JwtClaimNames.IAT,
        TokenXClaimNames.PID,
        TokenXClaimNames.ACR,
    )

/**
 * Decoder for TokenX tokens: RS256 only, keys from the JWKS endpoint, and every check in
 * [tokenXTokenValidator].
 */
public fun tokenXJwtDecoder(
    properties: TokenXAuthProperties,
    acceptedAcrValues: Set<String> = ACR_HIGH,
): JwtDecoder =
    NimbusJwtDecoder
        .withJwkSetUri(properties.jwksUri)
        .jwsAlgorithm(SignatureAlgorithm.RS256)
        .build()
        .apply {
            setJwtValidator(
                tokenXTokenValidator(
                    issuer = properties.issuer,
                    audience = properties.clientId,
                    acceptedAcrValues = acceptedAcrValues,
                ),
            )
        }

/**
 * Everything a TokenX token must satisfy after its signature has been verified.
 */
public fun tokenXTokenValidator(
    issuer: String,
    audience: String,
    acceptedAcrValues: Set<String> = ACR_HIGH,
): OAuth2TokenValidator<Jwt> =
    DelegatingOAuth2TokenValidator(
        JwtValidators.createDefaultWithIssuer(issuer),
        RequiredClaimsValidator(TOKENX_REQUIRED_CLAIMS),
        AudienceValidator(audience),
        AcrValidator(acceptedAcrValues),
    )

/**
 * Only accepts tokens where the citizen logged in at one of [acceptedAcrValues].
 */
public class AcrValidator(
    private val acceptedAcrValues: Set<String>,
) : OAuth2TokenValidator<Jwt> {
    init {
        require(acceptedAcrValues.isNotEmpty()) { "No accepted acr values configured." }
    }

    override fun validate(token: Jwt): OAuth2TokenValidatorResult =
        if (token.getClaimAsString(TokenXClaimNames.ACR) in acceptedAcrValues) {
            OAuth2TokenValidatorResult.success()
        } else {
            OAuth2TokenValidatorResult.failure(invalidToken("The acr claim is not an accepted login level."))
        }
}

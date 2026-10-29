package no.nav.klage.auth.test

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import no.nav.klage.auth.AZP_CLAIM
import no.nav.klage.auth.AzureAuthProperties
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback
import org.springframework.test.context.DynamicPropertyRegistry
import java.util.Date

/**
 * Azure AD for tests: a mock-oauth2-server that signs real tokens, so the whole validation chain
 * in the app runs, not only the URL rules.
 *
 * Register it with [registerProperties] from a `@DynamicPropertySource` method.
 */
public class MockAzure(
    public val clientId: String = DEFAULT_CLIENT_ID,
    public val preAuthorizedClientIds: Set<String> = setOf(DEFAULT_CALLER),
) : AutoCloseable {
    public companion object {
        public const val DEFAULT_CLIENT_ID: String = "test-app-client-id"
        public const val DEFAULT_CALLER: String = "test-caller-client-id"
        public const val NAV_IDENT_CLAIM: String = "NAVident"

        private const val ISSUER_ID = "azuread"
        private const val OTHER_ISSUER_ID = "other-issuer"
        private const val HOUR_IN_SECONDS = 3600L
        private const val HS256_SECRET_LENGTH = 32
    }

    public val server: MockOAuth2Server = MockOAuth2Server().apply { start() }

    public val issuer: String get() = server.issuerUrl(ISSUER_ID).toString()

    public fun registerProperties(registry: DynamicPropertyRegistry) {
        registry.add(AzureAuthProperties.ISSUER) { issuer }
        registry.add(AzureAuthProperties.JWKS_URI) { server.jwksUrl(ISSUER_ID).toString() }
        registry.add(AzureAuthProperties.CLIENT_ID) { clientId }
        registry.add(AzureAuthProperties.PRE_AUTHORIZED_APPS) {
            preAuthorizedClientIds.joinToString(prefix = "[", postfix = "]") { """{"name":"test:klage:$it","clientId":"$it"}""" }
        }
    }

    /**
     * A valid token by default. Add `NAVident` through [claims] to simulate an on-behalf-of token.
     */
    public fun token(
        azp: String = preAuthorizedClientIds.first(),
        audience: String = clientId,
        subject: String = "subject",
        claims: Map<String, Any> = emptyMap(),
        expirySeconds: Long = HOUR_IN_SECONDS,
    ): String =
        issue(issuerId = ISSUER_ID, azp = azp, audience = audience, subject = subject, claims = claims, expirySeconds = expirySeconds)

    /** Signed by a key the app does not trust, with another issuer. */
    public fun tokenFromOtherIssuer(): String =
        issue(
            issuerId = OTHER_ISSUER_ID,
            azp = preAuthorizedClientIds.first(),
            audience = clientId,
            subject = "subject",
            claims = emptyMap(),
            expirySeconds = HOUR_IN_SECONDS,
        )

    /** Valid claims, but signed with HS256 instead of RS256. */
    public fun hs256Token(): String =
        SignedJWT(JWSHeader(JWSAlgorithm.HS256), validClaims())
            .apply { sign(MACSigner(ByteArray(HS256_SECRET_LENGTH) { 1 })) }
            .serialize()

    /** Valid claims, but `alg=none`. */
    public fun unsignedToken(): String = PlainJWT(validClaims()).serialize()

    override fun close() {
        server.shutdown()
    }

    private fun issue(
        issuerId: String,
        azp: String,
        audience: String,
        subject: String,
        claims: Map<String, Any>,
        expirySeconds: Long,
    ): String =
        server
            .issueToken(
                issuerId = issuerId,
                clientId = azp,
                tokenCallback =
                    DefaultOAuth2TokenCallback(
                        issuerId = issuerId,
                        subject = subject,
                        audience = listOf(audience),
                        claims = claims + (AZP_CLAIM to azp),
                        expiry = expirySeconds,
                    ),
            ).serialize()

    private fun validClaims(): JWTClaimsSet {
        val now = System.currentTimeMillis()
        return JWTClaimsSet
            .Builder()
            .issuer(issuer)
            .subject("subject")
            .audience(clientId)
            .expirationTime(Date(now + HOUR_IN_SECONDS * 1000))
            .notBeforeTime(Date(now))
            .issueTime(Date(now))
            .claim(AZP_CLAIM, preAuthorizedClientIds.first())
            .build()
    }
}

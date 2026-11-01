package no.nav.klage.auth.test

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import no.nav.klage.auth.TokenXAuthProperties
import no.nav.klage.auth.TokenXClaimNames
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback
import org.springframework.test.context.DynamicPropertyRegistry
import java.util.Date

/**
 * TokenX for tests: a mock-oauth2-server that signs real tokens for a citizen, so the whole
 * validation chain in the app runs.
 *
 * Register it with [registerProperties] from a `@DynamicPropertySource` method.
 */
public class MockTokenX(
    public val clientId: String = DEFAULT_CLIENT_ID,
) : AutoCloseable {
    public companion object {
        public const val DEFAULT_CLIENT_ID: String = "dev-gcp:klage:test-app"
        public const val DEFAULT_PID: String = "12345678910"
        public const val DEFAULT_ACR: String = "idporten-loa-high"

        private const val ISSUER_ID = "tokenx"
        private const val OTHER_ISSUER_ID = "other-issuer"
        private const val CALLER = "dev-gcp:klage:test-frontend"
        private const val HOUR_IN_SECONDS = 3600L
        private const val HS256_SECRET_LENGTH = 32
    }

    public val server: MockOAuth2Server = MockOAuth2Server().apply { start() }

    public val issuer: String get() = server.issuerUrl(ISSUER_ID).toString()

    public fun registerProperties(registry: DynamicPropertyRegistry) {
        registry.add(TokenXAuthProperties.ISSUER) { issuer }
        registry.add(TokenXAuthProperties.JWKS_URI) { server.jwksUrl(ISSUER_ID).toString() }
        registry.add(TokenXAuthProperties.CLIENT_ID) { clientId }
    }

    /**
     * A valid token by default. Pass `pid = null` or `acr = null` to leave the claim out.
     */
    public fun token(
        pid: String? = DEFAULT_PID,
        acr: String? = DEFAULT_ACR,
        audience: String = clientId,
        claims: Map<String, Any> = emptyMap(),
        expirySeconds: Long = HOUR_IN_SECONDS,
    ): String =
        issue(
            issuerId = ISSUER_ID,
            audience = audience,
            claims = citizenClaims(pid = pid, acr = acr) + claims,
            expirySeconds = expirySeconds,
        )

    /** Signed by a key the app does not trust, with another issuer. */
    public fun tokenFromOtherIssuer(): String =
        issue(
            issuerId = OTHER_ISSUER_ID,
            audience = clientId,
            claims = citizenClaims(pid = DEFAULT_PID, acr = DEFAULT_ACR),
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

    private fun citizenClaims(
        pid: String?,
        acr: String?,
    ): Map<String, Any> =
        buildMap {
            pid?.let { put(key = TokenXClaimNames.PID, value = it) }
            acr?.let { put(key = TokenXClaimNames.ACR, value = it) }
        }

    private fun issue(
        issuerId: String,
        audience: String,
        claims: Map<String, Any>,
        expirySeconds: Long,
    ): String =
        server
            .issueToken(
                issuerId = issuerId,
                clientId = CALLER,
                tokenCallback =
                    DefaultOAuth2TokenCallback(
                        issuerId = issuerId,
                        subject = "subject",
                        audience = listOf(audience),
                        claims = claims,
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
            .claim(TokenXClaimNames.PID, DEFAULT_PID)
            .claim(TokenXClaimNames.ACR, DEFAULT_ACR)
            .build()
    }
}

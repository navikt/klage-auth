package no.nav.klage.auth

import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken

/**
 * The validated TokenX token for the current request, or null outside an authenticated request or
 * when the request has another kind of token. A TokenX token is recognised by its pid claim.
 *
 * Reads the thread bound security context, so it returns null on other threads, such as in
 * `@Async` methods. Read the claims you need before handing work to another thread.
 */
public fun currentTokenXToken(): Jwt? =
    (SecurityContextHolder.getContext().authentication as? JwtAuthenticationToken)
        ?.token
        ?.takeIf { it.pid != null }

/** The fødselsnummer of the citizen who logged in. */
public val Jwt.pid: String? get() = getClaimAsString(TokenXClaimNames.PID)

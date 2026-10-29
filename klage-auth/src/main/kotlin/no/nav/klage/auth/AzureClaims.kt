package no.nav.klage.auth

import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken

public object AzureClaimNames {
    public const val NAV_IDENT: String = "NAVident"
    public const val NAME: String = "name"
    public const val GROUPS: String = "groups"
    public const val AZP_NAME: String = "azp_name"
    public const val IDTYP: String = "idtyp"
}

public enum class AzureTokenType {
    /** Client credentials: the calling app acts on its own behalf. */
    CC,

    /** On-behalf-of: the calling app acts for a logged in Nav employee. */
    OBO,
    UNAUTHENTICATED,
}

/**
 * The validated token for the current request, or null outside an authenticated request.
 *
 * Reads the thread bound security context, so it returns null on other threads, such as in
 * `@Async` methods. Read the claims you need before handing work to another thread.
 */
public fun currentAzureToken(): Jwt? = (SecurityContextHolder.getContext().authentication as? JwtAuthenticationToken)?.token

/** The ident of the Nav employee. Only present in on-behalf-of tokens. */
public val Jwt.navIdent: String? get() = getClaimAsString(AzureClaimNames.NAV_IDENT)

/** The display name of the Nav employee. Only present in on-behalf-of tokens. */
public val Jwt.displayName: String? get() = getClaimAsString(AzureClaimNames.NAME)

/** Object ids of the Azure AD groups the Nav employee is a member of. Empty for client credentials tokens. */
public val Jwt.groups: List<String> get() = getClaimAsStringList(AzureClaimNames.GROUPS).orEmpty()

/**
 * Display name of the calling app, on the form `cluster:namespace:app`. Use it for logging only:
 * the app is identified by the `azp` claim, which the token validation checks.
 */
public val Jwt.callingApp: String? get() = getClaimAsString(AzureClaimNames.AZP_NAME)

public val Jwt.tokenType: AzureTokenType
    get() =
        when {
            getClaimAsString(AzureClaimNames.IDTYP) == "app" -> AzureTokenType.CC
            navIdent != null -> AzureTokenType.OBO
            else -> AzureTokenType.UNAUTHENTICATED
        }

/** [AzureTokenType.UNAUTHENTICATED] when there is no token for the current request. */
public fun currentAzureTokenType(): AzureTokenType = currentAzureToken()?.tokenType ?: AzureTokenType.UNAUTHENTICATED

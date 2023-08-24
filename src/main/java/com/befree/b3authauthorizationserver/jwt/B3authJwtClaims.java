package com.befree.b3authauthorizationserver.jwt;

/**
 * represents possible (and usually expected) token claims
 * @author Michał Chruścielski
 * @since 0.1
 */
public final class B3authJwtClaims {

    /**
     * issuing server hostname
     */
    public static final String ISSUER = "iss";

    /**
     * user id
     */
    public static final String SUBJECT = "sub";

    /**
     * might be set to list of resource server domains
     * optional
     */
    public static final String AUDIENCE = "aud";
    /**
     * date of expiration
     */
    public static final String EXPIRES_AT = "exp";

    /**
     * date when token starts working
     * optional
     */
    public static final String NOT_BEFORE = "nbf";

    /**
     * date of issue
     */
    public static final String ISSUED_AT = "iat";

    /**
     * token id
     * UUID preferred
     */
    public static final String JWT_ID = "jti";

    /**
     * user authorities list
     */
    public static final String AUTHORITIES = "atr";

    /**
     * user authorities list
     */
    public static final String TOKEN_TYPE = "tkp";
}
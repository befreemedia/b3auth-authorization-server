package com.befree.b3authauthorizationserver.config.configuration;

public final class B3authEndpointsList {
    public final static String USER_AUTHENTICATION = "b3auth/authenticate";
    public final static String USER_TOKEN_REVOCATION = "b3auth/revoke";
    public final static String USER_LOGOUT = "b3auth/logout";
    public final static String TOKEN_AUTHORIZATION = "b3auth/token/authorize";
    public final static String CLIENT_AUTHENTICATION = "b3auth/client/authenticate";
    public final static String CLIENT_USER_REGISTRATION = "b3auth/client/user";
    public final static String CLIENT_USER_ROLE = "b3auth/client/user/role";
    public final static String CLIENT_USER_PERMISSION = "b3auth/client/user/permission";
    public final static String CLIENT_TOKEN_REVOCATION = "b3auth/client/revoke";
    public final static String CLIENT_LOGOUT = "b3auth/client/logout";
    public final static String JWK = "b3auth/jwk";
}

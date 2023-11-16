package com.befree.b3authauthorizationserver.jwt;

import java.time.LocalDateTime;
import java.util.*;

public class AuthorizationToken extends Jwt {

    public AuthorizationToken(UUID uuid, String value, LocalDateTime expiresAt, LocalDateTime issuedAt,
                              Map<String, Object> claims) {
        super(uuid, value, expiresAt, issuedAt, claims);
    }

    @Override
    public String getType() {
        return B3authTokenType.AUTHORIZATION_TOKEN;
    }
}

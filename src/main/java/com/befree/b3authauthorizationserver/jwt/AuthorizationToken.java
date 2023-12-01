package com.befree.b3authauthorizationserver.jwt;

import com.befree.b3authauthorizationserver.B3authUser;

import java.time.LocalDateTime;
import java.util.*;

public class AuthorizationToken extends Jwt {

    public AuthorizationToken(UUID uuid, String value, LocalDateTime expiresAt, LocalDateTime issuedAt,
                              Map<String, Object> claims, Long subjectId) {
        super(uuid, value, expiresAt, issuedAt, claims, subjectId);
    }

    @Override
    public String getType() {
        return B3authTokenType.AUTHORIZATION_TOKEN;
    }
}

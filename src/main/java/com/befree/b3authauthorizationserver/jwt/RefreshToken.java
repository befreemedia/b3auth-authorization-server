package com.befree.b3authauthorizationserver.jwt;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

public class RefreshToken extends Jwt {
    public RefreshToken(UUID uuid, String value, LocalDateTime expiresAt, LocalDateTime issuedAt,
                              Map<String, Object> claims) {
        super(uuid, value, expiresAt, issuedAt, claims);
    }

    @Override
    public String getType() {
        return B3authTokenType.REFRESH_TOKEN;
    }
}

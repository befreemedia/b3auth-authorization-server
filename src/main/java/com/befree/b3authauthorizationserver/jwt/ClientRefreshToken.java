package com.befree.b3authauthorizationserver.jwt;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

public class ClientRefreshToken extends Jwt {
    public ClientRefreshToken(UUID uuid, String value, LocalDateTime expiresAt, LocalDateTime issuedAt,
                        Map<String, Object> claims, Long subjectId) {
        super(uuid, value, expiresAt, issuedAt, claims, subjectId);
    }

    @Override
    public String getType() {
        return B3authTokenType.CLIENT_REFRESH_TOKEN;
    }
}


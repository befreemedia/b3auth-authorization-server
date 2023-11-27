package com.befree.b3authauthorizationserver.jwt;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

public interface JwtToken {
    String getValue();
    LocalDateTime issuedAt();
    LocalDateTime expiresAt();
    Map<String, Object> getClaims();
}

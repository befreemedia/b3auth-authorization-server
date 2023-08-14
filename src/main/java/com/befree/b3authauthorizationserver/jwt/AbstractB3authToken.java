package com.befree.b3authauthorizationserver.jwt;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public abstract class AbstractB3authToken implements B3authToken {
    private final UUID uuid;
    private final String value;
    private final LocalDateTime expiresAt;
    private final LocalDateTime issuedAt;

    public AbstractB3authToken(UUID uuid, String value, LocalDateTime expiresAt, LocalDateTime issuedAt) {
        this.uuid = uuid;
        this.value = value;
        this.expiresAt = expiresAt;
        this.issuedAt = issuedAt;
    }

    @Override
    public LocalDateTime expiresAt() {
        return expiresAt;
    }

    @Override
    public LocalDateTime issuedAt() {
        return issuedAt;
    }

    @Override
    public UUID getId() {
        return uuid;
    }

    @Override
    public String getValue() {
        return value;
    }
}

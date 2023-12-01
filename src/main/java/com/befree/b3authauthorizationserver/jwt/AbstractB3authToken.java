package com.befree.b3authauthorizationserver.jwt;

import com.befree.b3authauthorizationserver.B3authUser;

import java.time.LocalDateTime;
import java.util.UUID;

public abstract class AbstractB3authToken implements B3authToken {
    private UUID uuid;
    private String value;
    private LocalDateTime expiresAt;
    private LocalDateTime issuedAt;
    private Long subjectId;

    public AbstractB3authToken(UUID uuid, String value, LocalDateTime expiresAt, LocalDateTime issuedAt, Long subjectId) {
        this.uuid = uuid;
        this.value = value;
        this.expiresAt = expiresAt;
        this.issuedAt = issuedAt;
        this.subjectId = subjectId;
    }

    public AbstractB3authToken() {
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

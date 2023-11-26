package com.befree.b3authauthorizationserver;

import java.time.LocalDateTime;


public class B3authDefaultAuthenticationAttempt implements B3authAuthenticationAttempt {
    private Long id;
    private Long userId;
    private String code;
    private LocalDateTime created;
    private boolean deleted;
    private boolean succeed;
    private boolean revoked;

    public B3authDefaultAuthenticationAttempt(Long id, Long userId, String code, LocalDateTime created, boolean deleted, boolean succeed, boolean revoked) {
        this.id = id;
        this.userId = userId;
        this.code = code;
        this.created = created;
        this.deleted = deleted;
        this.succeed = succeed;
        this.revoked = revoked;
    }

    public B3authDefaultAuthenticationAttempt() {
    }

    @Override
    public Long getId() {
        return id;
    }

    @Override
    public Long getUserId() {
        return userId;
    }

    @Override
    public String getCode() {
        return code;
    }

    @Override
    public LocalDateTime getCreated() {
        return created;
    }

    @Override
    public boolean isDeleted() {
        return this.deleted;
    }

    @Override
    public boolean isSucceed() {
        return this.succeed;
    }

    @Override
    public boolean isRevoked() {
        return this.revoked;
    }

    @Override
    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    @Override
    public void setSucceeded(boolean succeeded) {
        this.succeed = succeeded;
    }
}

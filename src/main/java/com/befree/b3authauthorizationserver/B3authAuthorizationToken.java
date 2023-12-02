package com.befree.b3authauthorizationserver;

import jakarta.annotation.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.UUID;

public class B3authAuthorizationToken extends AbstractAuthenticationToken {
    private final UUID sessionId;
    private final Long userId;
    private final boolean userInitialized;
    public B3authAuthorizationToken(UUID sessionId, Long userId, boolean userInitialized, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);

        this.sessionId = sessionId;
        this.userId = userId;
        this.userInitialized = userInitialized;

        super.setAuthenticated(true);
    }

    public B3authAuthorizationToken(UUID sessionId, Long userId, boolean userInitialized) {
        super(null);

        this.sessionId = sessionId;
        this.userId = userId;
        this.userInitialized = userInitialized;

        super.setAuthenticated(false);
    }

    public B3authAuthorizationToken(Long userId, boolean userInitialized) {
        super(null);

        this.userId = userId;
        this.userInitialized = userInitialized;
        this.sessionId = null;

        super.setAuthenticated(false);
    }

    @Override
    @Nullable
    public Object getCredentials() {
        return null;
    }

    @Override
    public Long getPrincipal() {
        return this.userId;
    }

    @Nullable
    public UUID getSessionId() {
        return sessionId;
    }

    public Long getUserId() {
        return userId;
    }

    public boolean isUserInitialized() {
        return userInitialized;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated, "Set only by constructor");
        super.setAuthenticated(false);
    }
}

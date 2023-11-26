package com.befree.b3authauthorizationserver;

import jakarta.annotation.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.UUID;

public class B3authClientAuthorizationToken extends AbstractAuthenticationToken {
    private final UUID sessionId;
    private final Long clientId;
    public B3authClientAuthorizationToken(UUID sessionId, Long clientId, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);

        this.sessionId = sessionId;
        this.clientId = clientId;

        super.setAuthenticated(true);
    }

    public B3authClientAuthorizationToken(UUID sessionId, Long clientId) {
        super(null);

        this.sessionId = sessionId;
        this.clientId = clientId;

        super.setAuthenticated(false);
    }

    public B3authClientAuthorizationToken(Long clientId) {
        super(null);

        this.clientId = clientId;
        this.sessionId = null;

        super.setAuthenticated(false);
    }

    @Override
    @Nullable
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.clientId;
    }

    @Nullable
    public UUID getSessionId() {
        return sessionId;
    }

    public Long getClientId() {
        return clientId;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        super.setAuthenticated(isAuthenticated);
    }
}

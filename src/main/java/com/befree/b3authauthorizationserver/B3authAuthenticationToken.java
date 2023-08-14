package com.befree.b3authauthorizationserver;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import javax.security.auth.Subject;
import java.util.Collection;
import java.util.UUID;

public class B3authAuthenticationToken extends AbstractAuthenticationToken {
    private final Authentication principal;
    private UUID tokenId;

    public B3authAuthenticationToken(Authentication principal, UUID tokenId, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        Assert.notNull(tokenId, "token id can't be null");
        Assert.notNull(principal, "principal can't be null");
        this.principal = principal;
        this.tokenId = tokenId;
        super.setAuthenticated(true);
    }

    public B3authAuthenticationToken(Authentication principal, UUID tokenId) {
        super(null);
        Assert.notNull(tokenId, "token id can't be null");
        Assert.notNull(principal, "principal can't be null");
        this.principal = principal;
        this.tokenId = tokenId;
    }

    @Override
    @Nullable
    public Object getCredentials() {
        return null;
    }

    @Override
    public Authentication getPrincipal() {
        return this.principal;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated, "Set only by constructor");
        super.setAuthenticated(false);
    }

    public UUID getTokenId() {
        return tokenId;
    }

    public UUID getPrincipalId() {
        return  UUID.fromString(this.getName());
    }
}

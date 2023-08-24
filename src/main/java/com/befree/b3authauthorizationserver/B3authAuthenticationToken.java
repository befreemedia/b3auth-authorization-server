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
    public B3authAuthenticationToken(Authentication principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        Assert.notNull(principal, "principal can't be null");
        this.principal = principal;
        super.setAuthenticated(true);
    }

    public B3authAuthenticationToken(Authentication principal) {
        super(null);
        Assert.notNull(principal, "principal can't be null");
        this.principal = principal;
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

    public UUID getPrincipalId() {
        return  UUID.fromString(this.getName());
    }
}

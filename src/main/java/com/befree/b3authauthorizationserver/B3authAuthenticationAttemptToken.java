package com.befree.b3authauthorizationserver;

import jakarta.annotation.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;

public class B3authAuthenticationAttemptToken extends AbstractAuthenticationToken {
    private final String email;
    public B3authAuthenticationAttemptToken(String email) {
        super(null);
        Assert.hasText(email, "principal can't be null");
        this.email = email;
        super.setAuthenticated(false);
    }

    @Override
    @Nullable
    public Object getCredentials() {
        return null;
    }

    @Override
    public String getPrincipal() {
        return this.email;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated, "Set only by constructor");
        super.setAuthenticated(false);
    }
}


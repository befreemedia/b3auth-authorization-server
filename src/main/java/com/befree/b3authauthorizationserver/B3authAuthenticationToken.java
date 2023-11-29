package com.befree.b3authauthorizationserver;

import jakarta.annotation.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;

public class B3authAuthenticationToken extends AbstractAuthenticationToken {
    private final String email;
    private final String code;
    public B3authAuthenticationToken(String email, String code, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        Assert.hasText(email, "principal can't be null");
        Assert.hasText(code, "code have to contain numbers");
        this.email = email;
        this.code = code;
        super.setAuthenticated(true);
    }

    public B3authAuthenticationToken(String email, String code) {
        super(null);
        Assert.hasText(email, "principal can't be null");
        Assert.hasText(code, "code have to contain numbers");
        this.email = email;
        this.code = code;
    }

    @Override
    @Nullable
    public Object getCredentials() {
        return code;
    }

    @Override
    public String getPrincipal() {
        return this.email;
    }

    public String getEmail() {
        return email;
    }

    public String getCode() {
        return code;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated, "Set only by constructor");
        super.setAuthenticated(false);
    }
}

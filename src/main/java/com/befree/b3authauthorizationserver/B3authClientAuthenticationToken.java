package com.befree.b3authauthorizationserver;

import jakarta.annotation.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;

public class B3authClientAuthenticationToken extends AbstractAuthenticationToken {
    private final String login;
    private final String password;
    public B3authClientAuthenticationToken(String login, String password, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        Assert.hasText(login, "principal can't be null");
        Assert.hasText(password, "Password have to contain text");
        this.login = login;
        this.password = password;
        super.setAuthenticated(true);
    }

    public B3authClientAuthenticationToken(String login, String password) {
        super(null);
        Assert.hasText(login, "principal can't be null");
        Assert.hasText(password, "Password have to contain text");
        this.login = login;
        this.password = password;
    }

    @Override
    @Nullable
    public Object getCredentials() {
        return null;
    }

    @Override
    public String getPrincipal() {
        return this.login;
    }

    public String getLogin() {
        return login;
    }

    public String getPassword() {
        return password;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated, "Set to true only by constructor");
        super.setAuthenticated(false);
    }
}

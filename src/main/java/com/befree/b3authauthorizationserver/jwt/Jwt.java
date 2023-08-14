package com.befree.b3authauthorizationserver.jwt;

import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

public abstract class Jwt extends AbstractB3authToken implements JwtToken, JwtClaimsAccessor {

    private final Map<String, Object> claims;


    public Jwt(UUID uuid, String value, LocalDateTime expiresAt, LocalDateTime issuedAt,
               Map<String, Object> claims) {

        super(uuid, value, expiresAt, issuedAt);
        this.claims = claims;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return JwtClaimsAccessor.super.getAuthorities();
    }

    @Override
    public Map<String, Object> getClaims() {
        return this.claims;
    }
}

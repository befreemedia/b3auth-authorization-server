package com.befree.b3authauthorizationserver.jwt;

import com.befree.b3authauthorizationserver.B3authAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Stream;

public class B3authAuthorizationToken extends Jwt {

    public B3authAuthorizationToken(UUID uuid, String value, LocalDateTime expiresAt, LocalDateTime issuedAt,
                                    Map<String, Object> claims) {
        super(uuid, value, expiresAt, issuedAt, claims);
    }

    @Override
    public String getType() {
        return B3authTokenType.AUTHORIZATION_TOKEN;
    }
}

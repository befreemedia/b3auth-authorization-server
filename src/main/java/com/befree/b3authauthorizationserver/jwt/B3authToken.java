package com.befree.b3authauthorizationserver.jwt;

import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.UUID;

public interface B3authToken {
    UUID getId();
    String getValue();
    LocalDateTime issuedAt();
    LocalDateTime expiresAt();
    String getType();
    Collection<? extends GrantedAuthority> getAuthorities();
}

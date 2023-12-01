package com.befree.b3authauthorizationserver;

import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.UUID;

public interface B3authSession {
    UUID getId();
    Long getSubjectId();
    String getType();
    LocalDateTime getIssuedAt();
    LocalDateTime getExpiresAt();
    LocalDateTime getRefreshExpiresAt();
    Collection<? extends GrantedAuthority> getAuthorities();
    Boolean getDeleted();
    Boolean getRevoked();
    Boolean getSuspended();
}

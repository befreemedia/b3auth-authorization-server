package com.befree.b3authauthorizationserver;

import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.UUID;

public interface B3authRole extends GrantedAuthority {
    UUID getId();
    String getName();
    String getValue();
    UUID getOwnerId();
    LocalDateTime getCreated();
    Collection<? extends B3authPermission> getPermissions();

}

package com.befree.b3authauthorizationserver;

import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.UUID;

public interface B3authUser {
    UUID getId();
    String getEmail();
    LocalDateTime getCreated();
    Collection<? extends B3authRole> getRoles();
    boolean initialised();
    boolean suspended();
    boolean banned();
    boolean locked();
    boolean deleted();
}
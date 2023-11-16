package com.befree.b3authauthorizationserver;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.UUID;

public interface B3authUser extends UserDetails {
    Long getId();
    String getEmail();
    LocalDateTime getCreated();
    Collection<? extends B3authRole> getRoles();
    boolean initialised();
    boolean suspended();
    boolean banned();
    boolean locked();
    boolean deleted();
}
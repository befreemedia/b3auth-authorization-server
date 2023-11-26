package com.befree.b3authauthorizationserver;

import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;

public interface B3authClient extends UserDetails {
    Long getId();
    LocalDateTime getCreated();
    String getName();
    Collection<? extends B3authRole> getRoles();
    boolean initialised();
    boolean suspended();
    boolean banned();
    boolean locked();
    boolean deleted();
}

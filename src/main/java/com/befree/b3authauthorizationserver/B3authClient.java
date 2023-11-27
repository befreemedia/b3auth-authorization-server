package com.befree.b3authauthorizationserver;

import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;

public interface B3authClient {
    Long getId();
    LocalDateTime getCreated();
    String getName();
    String getPassword();
    String getLogin();
    boolean getInitialised();
    boolean getSuspended();
    boolean getBanned();
    boolean getLocked();
    boolean getDeleted();
}

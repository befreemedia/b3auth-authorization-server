package com.befree.b3authauthorizationserver;

import java.time.LocalDateTime;
import java.util.Collection;

public interface B3authAuthenticationAttempt {
    Long getId();
    Long getUserId();
    String getCode();
    LocalDateTime getCreated();
    boolean deleted();
    boolean succeed();
    boolean revoked();

}

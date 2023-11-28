package com.befree.b3authauthorizationserver;

import java.time.LocalDateTime;

public interface B3authAuthenticationAttempt {
    Long getId();
    Long getUserId();
    String getCode();
    LocalDateTime getCreated();
    boolean isDeleted();
    boolean isSucceed();
    boolean isRevoked();
    void setRevoked(boolean revoked);
    void setSucceed(boolean succeeded);

}

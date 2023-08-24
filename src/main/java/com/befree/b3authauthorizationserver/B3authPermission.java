package com.befree.b3authauthorizationserver;

import java.time.LocalDateTime;
import java.util.UUID;

public interface B3authPermission {
    UUID getId();
    String getName();
    String getValue();
    LocalDateTime getCreated();
}

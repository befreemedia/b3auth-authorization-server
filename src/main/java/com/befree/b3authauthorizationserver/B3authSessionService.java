package com.befree.b3authauthorizationserver;

import com.befree.b3authauthorizationserver.jwt.B3authToken;
import org.springframework.lang.Nullable;

import java.util.UUID;

public interface B3authSessionService {
        void save(B3authToken token);

        void remove(B3authToken token);

        void removeById(UUID id);

        @Nullable
        B3authToken findById(UUID id);
}

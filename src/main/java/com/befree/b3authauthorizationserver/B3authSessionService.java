package com.befree.b3authauthorizationserver;

import com.befree.b3authauthorizationserver.jwt.B3authToken;
import org.springframework.lang.Nullable;

import java.util.UUID;

public interface B3authSessionService {
        void save(B3authSession session);

        void remove(B3authSession session);

        void removeById(UUID id);

        @Nullable
        B3authSession findById(UUID id);
}

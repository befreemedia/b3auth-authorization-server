package com.befree.b3authauthorizationserver;

import com.befree.b3authauthorizationserver.jwt.B3authToken;
import com.befree.b3authauthorizationserver.jwt.B3authTokenType;
import org.springframework.lang.Nullable;

import java.util.UUID;

public interface B3authTokenService {
        void save(B3authToken token);

        void remove(B3authToken token);

        void removeById(UUID id);

        @Nullable
        B3authToken findById(UUID id);

        @Nullable
        B3authToken findByToken(String token, B3authTokenType tokenType);

        @Nullable
        B3authToken findByToken(String token);
}

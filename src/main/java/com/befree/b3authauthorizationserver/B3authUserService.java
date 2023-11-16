package com.befree.b3authauthorizationserver;

import com.befree.b3authauthorizationserver.jwt.B3authToken;
import com.befree.b3authauthorizationserver.jwt.B3authTokenType;
import org.springframework.lang.Nullable;

import java.util.UUID;

public interface B3authUserService {
    void save(B3authToken token);

    void remove(B3authToken token);

    void removeById(Long id);

    @Nullable
    B3authToken findById(Long id);

    @Nullable
    B3authUser findByEmail(String email);

    @Nullable
    B3authUser findByToken(String token, B3authTokenType tokenType);

    @Nullable
    B3authUser findByToken(String token);
}

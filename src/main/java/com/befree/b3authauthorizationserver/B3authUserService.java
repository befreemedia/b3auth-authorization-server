package com.befree.b3authauthorizationserver;

import com.befree.b3authauthorizationserver.jwt.B3authToken;
import com.befree.b3authauthorizationserver.jwt.B3authTokenType;
import org.springframework.lang.Nullable;

import java.util.UUID;

public interface B3authUserService {
    void save(B3authUser user);

    void createAndSaveEmail(String email);

    void remove(B3authUser user);

    void removeById(Long id);

    @Nullable
    B3authClient findById(Long id);

    @Nullable
    B3authUser findByEmail(String email);
}

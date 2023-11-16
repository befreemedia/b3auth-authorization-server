package com.befree.b3authauthorizationserver;

import com.befree.b3authauthorizationserver.jwt.B3authToken;
import com.befree.b3authauthorizationserver.jwt.B3authTokenType;
import org.springframework.lang.Nullable;

public interface B3authAuthenticationAttemptService {
    void save(B3authAuthenticationAttempt token);

    void remove(B3authAuthenticationAttempt token);

    void removeById(Long id);

    @Nullable
    B3authAuthenticationAttempt findById(Long id);

    @Nullable
    B3authAuthenticationAttempt findLastAttemptByUserId(Long id);
}

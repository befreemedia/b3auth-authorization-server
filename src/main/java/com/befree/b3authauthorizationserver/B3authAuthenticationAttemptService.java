package com.befree.b3authauthorizationserver;

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

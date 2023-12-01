package com.befree.b3authauthorizationserver;

import org.springframework.lang.Nullable;

public interface B3authAuthenticationAttemptService {
    void save(B3authAuthenticationAttempt token);

    void create(B3authUser user, String code);
    @Nullable
    B3authAuthenticationAttempt findById(Long id);

    @Nullable
    B3authAuthenticationAttempt findLastAttemptByUserId(Long id);
}

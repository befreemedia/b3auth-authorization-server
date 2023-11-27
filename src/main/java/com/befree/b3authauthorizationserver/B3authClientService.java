package com.befree.b3authauthorizationserver;

import org.springframework.lang.Nullable;

public interface B3authClientService {
    @Nullable
    B3authClient findById(Long id);

    @Nullable
    B3authClient findByLogin(String login);
}

package com.befree.b3authauthorizationserver;

import org.springframework.lang.Nullable;

public interface B3authUserService {
    void createAndSaveByEmail(String email);

    @Nullable
    B3authUser findById(Long id);

    @Nullable
    B3authUser findByEmail(String email);
}

package com.befree.b3authauthorizationserver;

import com.befree.b3authauthorizationserver.jwt.B3authToken;
import com.befree.b3authauthorizationserver.jwt.B3authTokenType;
import org.springframework.lang.Nullable;

public interface B3authClientService {
    void save(B3authClient client);

    void remove(B3authClient client);

    void removeById(Long id);

    @Nullable
    B3authClient findById(Long id);

    @Nullable
    B3authClient findByLogin(String login);
}

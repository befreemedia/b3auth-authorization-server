package com.befree.b3authauthorizationserver;

import com.befree.b3authauthorizationserver.jwt.Jwt;

public interface B3authSessionGenerator {
    B3authSession generate(Jwt authorizationToken, Jwt refreshToken, B3authClientAuthorizationToken b3authClientAuthorizationToken);

    B3authSession generate(Jwt authorizationToken, Jwt refreshToken, B3authAuthorizationToken b3authAuthorizationToken);

}

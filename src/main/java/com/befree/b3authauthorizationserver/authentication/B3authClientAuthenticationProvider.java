package com.befree.b3authauthorizationserver.authentication;

import com.befree.b3authauthorizationserver.*;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class B3authClientAuthenticationProvider implements AuthenticationProvider {
    private final B3authClientService b3authClientService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public B3authClientAuthenticationProvider(B3authClientService b3authClientService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.b3authClientService = b3authClientService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        B3authClientAuthenticationToken b3authClientAuthenticationToken = (B3authClientAuthenticationToken) authentication;
        B3authClient client = b3authClientService.findByLogin(b3authClientAuthenticationToken.getLogin());

        if(client == null) {
            throw new B3authAuthenticationException("Client cannot be found in database.",
                    "Client does not exists.", B3authAuthorizationServerExceptionCode.B4005);
        }

        if(client.banned() || client.deleted() || client.suspended() || client.locked()) {
            throw new B3authAuthenticationException("Client can't sign in.",
                    "Client account must be active to sign in.", B3authAuthorizationServerExceptionCode.B4008);
        }

        if(!bCryptPasswordEncoder.matches(b3authClientAuthenticationToken.getPassword(), client.getPassword())) {
            throw new B3authAuthenticationException("Wrong password",
                    "Password incorrect.",
                    B3authAuthorizationServerExceptionCode.B4009);
        }

        return new B3authClientAuthorizationToken(null, client.getId(), client.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return B3authClientAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

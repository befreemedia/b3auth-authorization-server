package com.befree.b3authauthorizationserver.authentication;

import com.befree.b3authauthorizationserver.*;
import com.befree.b3authauthorizationserver.config.configuration.CodeGenerator;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class B3authUserAuthenticationAttemptProvider implements AuthenticationProvider {
    private final B3authUserService b3authUserService;
    private final B3authAuthenticationAttemptService b3authAuthenticationAttemptService;

    public B3authUserAuthenticationAttemptProvider(B3authUserService b3authUserService,
                                                   B3authAuthenticationAttemptService b3authAuthenticationAttemptService) {
        this.b3authUserService = b3authUserService;
        this.b3authAuthenticationAttemptService = b3authAuthenticationAttemptService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        B3authAuthenticationAttemptToken b3authAuthenticationAttemptToken = (B3authAuthenticationAttemptToken) authentication;
        B3authUser user = b3authUserService.findByEmail(b3authAuthenticationAttemptToken.getEmail());

        if(user == null) {
            b3authUserService.createAndSaveEmail(b3authAuthenticationAttemptToken.getEmail());
            user = b3authUserService.findByEmail(b3authAuthenticationAttemptToken.getEmail());
        }

        if(user == null) {
            throw new B3authAuthenticationException("User cannot be found in database.",
                    "User does not exists and can't be created.", B3authAuthorizationServerExceptionCode.B4005);
        }

        B3authAuthenticationAttempt lastAuthenticationAttempt
                = b3authAuthenticationAttemptService.findLastAttemptByUserId(user.getId());

        if(lastAuthenticationAttempt != null) {
            lastAuthenticationAttempt.setRevoked(true);
            b3authAuthenticationAttemptService.save(lastAuthenticationAttempt);
        }

        String code = CodeGenerator.generate(6);

        b3authAuthenticationAttemptService.save();

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("auth");
        message.setTo(request.getEmail());
        message.setSubject("Your verification code");
        message.setText(code);
        javaMailSender.send(message);



        return new B3authAuthorizationToken(null, user.getId(), user.initialised(), user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return B3authAuthenticationAttemptToken.class.isAssignableFrom(authentication);
    }
}

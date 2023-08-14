package com.befree.b3authauthorizationserver;

import jakarta.annotation.Nullable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

import java.io.Serializable;

public class B3authAuthenticationException extends AuthenticationException {
    private final String description;
    private final String errorCode;

    public B3authAuthenticationException(String message) {
        super(message);
        Assert.hasText(message, "error code is required in this constructor");
        this.errorCode = null;
        this.description = null;
    }

    public B3authAuthenticationException(String message, String description) {
        super(message);
        Assert.hasText(description, "description text is required in this constructor");
        Assert.hasText(message, "message text is required in this constructor");
        this.errorCode = null;
        this.description = description;
    }

    public B3authAuthenticationException(String message, String description, String errorCode) {
        super(message);
        Assert.hasText(message, "message text is required in this constructor");
        Assert.hasText(errorCode, "message text is required in this constructor");
        Assert.hasText(description, "description text is required in this constructor");
        this.errorCode = errorCode;
        this.description = description;
    }

    public B3authAuthenticationException(String message, Throwable cause) {
        super(message, cause);
        Assert.hasText(message, "error code is required in this constructor");
        this.errorCode = null;
        this.description = null;
    }

    public B3authAuthenticationException(String message, String description, Throwable cause) {
        super(message, cause);
        Assert.hasText(description, "description text is required in this constructor");
        Assert.hasText(message, "message text is required in this constructor");
        this.errorCode = null;
        this.description = description;
    }

    public B3authAuthenticationException(String message, String description, String errorCode, Throwable cause) {
        super(message, cause);
        Assert.hasText(message, "message text is required in this constructor");
        Assert.hasText(errorCode, "message text is required in this constructor");
        Assert.hasText(description, "description text is required in this constructor");
        this.errorCode = errorCode;
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public String getErrorCode() {
        return errorCode;
    }
}

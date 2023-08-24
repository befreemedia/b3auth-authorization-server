package com.befree.b3authauthorizationserver;

import org.springframework.util.Assert;

public class B3authExceptionFrame {
    private final String errorCode;
    private final String errorName;


    public B3authExceptionFrame(String errorCode, String errorName) {
        Assert.hasText(errorCode, "error code should have text.");
        Assert.hasText(errorName, "error name should have text.");
        this.errorCode = errorCode;
        this.errorName = errorName;
    }

    @Override
    public String toString() {
        return errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getErrorName() {
        return errorName;
    }
}

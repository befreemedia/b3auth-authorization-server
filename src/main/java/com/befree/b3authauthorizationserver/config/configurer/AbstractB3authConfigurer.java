package com.befree.b3authauthorizationserver.config.configurer;

import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.RequestMatcher;

abstract class AbstractB3authConfigurer {
    private final ObjectPostProcessor<Object> objectPostProcessor;

    AbstractB3authConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
        this.objectPostProcessor = objectPostProcessor;
    }

    abstract void init(HttpSecurity httpSecurity);

    abstract void configure(HttpSecurity httpSecurity);

    protected final <T> T postProcess(T object) {
        return (T) this.objectPostProcessor.postProcess(object);
    }

    protected final ObjectPostProcessor<Object> getObjectPostProcessor() {
        return this.objectPostProcessor;
    }

}

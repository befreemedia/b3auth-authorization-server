package com.befree.b3authauthorizationserver.settings;

import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public abstract class AbstractSettings {
    private final Map<String, Object> settings;

    protected AbstractSettings(Map<String, Object> settings) {
        Assert.notEmpty(settings, "settings cannot be empty");
        this.settings = Collections.unmodifiableMap(settings);
    }

    public <T> T getSetting(String name) {
        Assert.hasText(name, "name cannot be empty");
        return (T) this.getSettings().get(name);
    }

    public Map<String, Object> getSettings() {
        return this.settings;
    }

    protected abstract static class AbstractBuilder<T extends AbstractSettings, B extends AbstractBuilder<T, B>> {
        private final Map<String, Object> settings = new HashMap();

        protected AbstractBuilder() {
        }

        public B setting(String name, Object value) {
            Assert.hasText(name, "name cannot be empty");
            Assert.notNull(value, "value cannot be null");
            this.getSettings().put(name, value);
            return this.getThis();
        }

        public B settings(Consumer<Map<String, Object>> settingsConsumer) {
            settingsConsumer.accept(this.getSettings());
            return this.getThis();
        }

        public abstract T build();

        protected final Map<String, Object> getSettings() {
            return this.settings;
        }

        protected final B getThis() {
            return (B) this;
        }
    }
}

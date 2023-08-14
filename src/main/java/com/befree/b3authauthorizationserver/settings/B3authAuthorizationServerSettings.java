package com.befree.b3authauthorizationserver.settings;

import com.befree.b3authauthorizationserver.settings.B3authSettingsSpace.*;
import org.springframework.util.Assert;

import java.util.Map;

public class B3authAuthorizationServerSettings extends AbstractSettings {
    private B3authAuthorizationServerSettings(Map<String, Object> settings) {
        super(settings);
    }

    public String getIssuer() {
        return this.getSetting(Main.ISSUER);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder withSettings(Map<String, Object> settings) {
        Assert.notEmpty(settings, "settings cannot be empty");
        return new Builder().settings((s) -> s.putAll(settings));
    }

    public static final class Builder extends AbstractSettings.AbstractBuilder<B3authAuthorizationServerSettings, Builder> {

        public Builder issuer(String issuer) {
            return this.setting(Main.ISSUER, issuer);
        }

        public B3authAuthorizationServerSettings build() {
            return new B3authAuthorizationServerSettings(this.getSettings());
        }
    }
}

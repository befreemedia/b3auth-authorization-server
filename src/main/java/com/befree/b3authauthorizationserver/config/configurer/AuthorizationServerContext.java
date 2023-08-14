package com.befree.b3authauthorizationserver.config.configurer;

import com.befree.b3authauthorizationserver.settings.B3authAuthorizationServerSettings;

public interface AuthorizationServerContext {
    String getIssuer();

    B3authAuthorizationServerSettings authorizationServerSettings();
}

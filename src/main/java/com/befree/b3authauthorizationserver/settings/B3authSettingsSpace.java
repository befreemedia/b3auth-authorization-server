package com.befree.b3authauthorizationserver.settings;

public final class B3authSettingsSpace {
    private static final String SETTINGS_NAMESPACE = "settings.";

    public static final class Token {
        private static final String TOKEN_SETTINGS_NAMESPACE = "settings.".concat("token.");

        static {

        }
    }

    public static final class Main {
        private static final String AUTHORIZATION_SERVER_SETTINGS_NAMESPACE = "settings.".concat("authorization-server.");
        public static final String ISSUER;

        static {
            ISSUER = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE.concat("issuer");
        }
    }

    public static final class Client {
        private static final String CLIENT_SETTINGS_NAMESPACE = "settings.".concat("client.");


        static {

        }
    }
}

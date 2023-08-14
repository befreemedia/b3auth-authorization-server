package com.befree.b3authauthorizationserver.config.configurer;

public final class AuthorizationServerContextHolder {
    private static final ThreadLocal<AuthorizationServerContext> holder = new ThreadLocal<AuthorizationServerContext>();

    public static AuthorizationServerContext getContext() {
        return holder.get();
    }

    public static void setContext(AuthorizationServerContext authorizationServerContext) {
        if (authorizationServerContext == null) {
            resetContext();
        } else {
            holder.set(authorizationServerContext);
        }
    }

    public static void resetContext() {
        holder.remove();
    }
}

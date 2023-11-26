package com.befree.b3authauthorizationserver.config.configuration;

import java.util.Random;

public class CodeGenerator {

    public static String generate(int len) {
        String AB = "0123456789";
        Random rnd = new Random();

        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(AB.charAt(rnd.nextInt(AB.length())));
        }
        return sb.toString();
    }
}

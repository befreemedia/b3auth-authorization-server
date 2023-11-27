package com.befree.b3authauthorizationserver.config.configuration;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@ComponentScan(basePackageClasses = B3authConfiguration.class)
@Configuration
@PropertySource(value = "classpath:b3-authorization-server-application.yml")
public class B3authConfiguration {
}
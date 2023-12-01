package com.befree.b3authauthorizationserver.config.configuration;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.annotation.AnnotationBeanNameGenerator;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

final class RegisterMissingBeanPostProcessor implements BeanDefinitionRegistryPostProcessor, BeanFactoryAware {
    private final AnnotationBeanNameGenerator beanNameGenerator = new AnnotationBeanNameGenerator();
    private final List<AbstractBeanDefinition> beanDefinitions = new ArrayList<>();
    private BeanFactory beanFactory;

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
        for (AbstractBeanDefinition beanDefinition : this.beanDefinitions) {
            String[] beanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
                    (ListableBeanFactory) this.beanFactory, beanDefinition.getBeanClass(), false, false);
            if (beanNames.length == 0) {
                String beanName = this.beanNameGenerator.generateBeanName(beanDefinition, registry);
                registry.registerBeanDefinition(beanName, beanDefinition);
            }
        }
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
    }

    <T> void addBeanDefinition(Class<T> beanClass, Supplier<T> beanSupplier) {
        this.beanDefinitions.add(new RootBeanDefinition(beanClass, beanSupplier));
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = beanFactory;
    }

}

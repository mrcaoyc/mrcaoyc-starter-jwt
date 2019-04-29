package com.github.mrcaoyc.starter.jwt;

import com.github.mrcaoyc.security.AuthorizationFilter;
import com.github.mrcaoyc.security.TokenProperties;
import com.github.mrcaoyc.starter.keygen.KeyGenerator;
import io.jsonwebtoken.Jwts;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

/**
 * @author CaoYongCheng
 */
@SpringBootConfiguration
@EnableConfigurationProperties({JwtTokenProperties.class, TokenProperties.class})
@ConditionalOnClass({Jwts.class, KeyGenerator.class})
@ConditionalOnProperty(prefix = "security", name = "enabled", havingValue = "true", matchIfMissing = true)
public class JwtAuthorizationAutoConfigure {

    @Bean
    @ConditionalOnBean(value = KeyGenerator.class)
    public FilterRegistrationBean<AuthorizationFilter> authorizationFilterFilterRegistrationBean(JwtTokenProperties jwtTokenProperties, KeyGenerator keyGenerator) {
        JwtTokenGenerator jwtTokenGenerator = new JwtTokenGenerator(jwtTokenProperties, keyGenerator);
        JwtAuthorizationFilter jwtAuthorizationFilter = new JwtAuthorizationFilter(jwtTokenProperties, jwtTokenGenerator);
        FilterRegistrationBean<AuthorizationFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(jwtAuthorizationFilter);
        registration.setOrder(jwtTokenProperties.getOrder());
        registration.setUrlPatterns(jwtTokenProperties.getIncludeUrls());
        return registration;
    }
}

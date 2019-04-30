package com.github.mrcaoyc.starter.jwt;

import com.github.mrcaoyc.security.AuthorizationFilter;
import com.github.mrcaoyc.security.TokenGenerator;
import com.github.mrcaoyc.security.TokenProperties;
import com.github.mrcaoyc.starter.keygen.KeyGenerator;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
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
    private final TokenProperties tokenProperties;
    private final JwtTokenProperties jwtTokenProperties;
    private final KeyGenerator keyGenerator;

    @Autowired
    public JwtAuthorizationAutoConfigure(TokenProperties tokenProperties, JwtTokenProperties jwtTokenProperties, KeyGenerator keyGenerator) {
        this.tokenProperties = tokenProperties;
        this.jwtTokenProperties = jwtTokenProperties;
        this.keyGenerator = keyGenerator;
    }

    @Bean
    @ConditionalOnBean(value = KeyGenerator.class)
    public FilterRegistrationBean<AuthorizationFilter> authorizationFilterFilterRegistrationBean() {
        JwtAuthorizationFilter jwtAuthorizationFilter = jwtAuthorizationFilter();
        FilterRegistrationBean<AuthorizationFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(jwtAuthorizationFilter);
        registration.setOrder(tokenProperties.getOrder());
        registration.setUrlPatterns(tokenProperties.getIncludeUrls());
        return registration;
    }

    @Bean
    @ConditionalOnBean(value = KeyGenerator.class)
    public JwtAuthorizationFilter jwtAuthorizationFilter() {
        JwtTokenGenerator jwtTokenGenerator = new JwtTokenGenerator(tokenProperties, jwtTokenProperties, keyGenerator);
        return new JwtAuthorizationFilter(tokenProperties, jwtTokenGenerator);
    }

    @Bean
    @ConditionalOnBean(value = KeyGenerator.class)
    @ConditionalOnMissingBean(TokenGenerator.class)
    public TokenGenerator tokenGenerator() {
        return new JwtTokenGenerator(tokenProperties, jwtTokenProperties, keyGenerator);
    }
}

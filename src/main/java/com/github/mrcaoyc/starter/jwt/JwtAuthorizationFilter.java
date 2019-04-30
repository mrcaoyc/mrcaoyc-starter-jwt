package com.github.mrcaoyc.starter.jwt;

import com.github.mrcaoyc.common.exception.runtime.UnauthorizedException;
import com.github.mrcaoyc.security.AuthorizationFilter;
import com.github.mrcaoyc.security.TokenProperties;
import com.github.mrcaoyc.security.event.AuthorizationEvent;
import org.springframework.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * @author CaoYongCheng
 */
public class JwtAuthorizationFilter extends AuthorizationFilter {
    private JwtTokenGenerator jwtTokenGenerator;


    public JwtAuthorizationFilter(TokenProperties tokenProperties, JwtTokenGenerator jwtTokenGenerator) {
        super(tokenProperties);
        this.jwtTokenGenerator = jwtTokenGenerator;
    }

    @Override
    protected boolean before(HttpServletRequest request, HttpServletResponse response, String token) {
        try {
            Map<String, Object> payload = jwtTokenGenerator.parseAccessToken(token);
            AuthorizationEvent authorizationEvent = new AuthorizationEvent(payload);
            super.authenticationSuccess(authorizationEvent);
            return true;
        } catch (UnauthorizedException e) {
            writeErrorMessage(response, e.getErrorMessage(), HttpStatus.UNAUTHORIZED);
            return false;
        }
    }
}

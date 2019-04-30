package com.github.mrcaoyc.starter.jwt;

import com.github.mrcaoyc.common.exception.runtime.CredentialsInvalidException;
import com.github.mrcaoyc.common.exception.runtime.CredentialsNotFoundException;
import com.github.mrcaoyc.common.exception.runtime.CredentialsTimeoutException;
import com.github.mrcaoyc.security.Token;
import com.github.mrcaoyc.security.TokenErrorMessage;
import com.github.mrcaoyc.security.TokenGenerator;
import com.github.mrcaoyc.security.TokenProperties;
import com.github.mrcaoyc.starter.keygen.KeyGenerator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * @author CaoYongCheng
 */
@Slf4j
public class JwtTokenGenerator implements TokenGenerator {
    private final String TOKEN_TYPE_KEY = "token_type";
    private final String ACCESS_TYPE_VALUE = "accessToken";
    private final String REFRESH_TYPE_VALUE = "refreshToken";
    private final TokenProperties tokenProperties;
    private final JwtTokenProperties jwtTokenProperties;
    private final KeyGenerator keyGenerator;

    public JwtTokenGenerator(TokenProperties tokenProperties, JwtTokenProperties jwtTokenProperties, KeyGenerator keyGenerator) {
        this.tokenProperties = tokenProperties;
        this.jwtTokenProperties = jwtTokenProperties;
        this.keyGenerator = keyGenerator;
    }

    @Override
    public Token createToken(Map<String, Object> payload) {
        if (payload == null) {
            payload = new HashMap<>(1);
        }
        Token token = new Token();
        token.setAccessToken(createAccessToken(payload, token));
        token.setRefreshToken(createRefreshToken(payload, token));
        token.setExpiresIn(tokenProperties.getExpiresIn());
        return token;
    }

    @Override
    public Map<String, Object> parseAccessToken(String accessToken) {
        if (StringUtils.isEmpty(accessToken) || "".equals(accessToken.trim())) {
            throw new CredentialsNotFoundException(TokenErrorMessage.ACCESS_TOKEN_MISSING);
        }
        String secret = jwtTokenProperties.getSecret();
        try {
            Claims body = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(accessToken.replace(jwtTokenProperties.getType() + " ", ""))
                    .getBody();
            if (Objects.equals(body.get(TOKEN_TYPE_KEY), ACCESS_TYPE_VALUE)) {
                return body;
            } else {
                throw new CredentialsInvalidException(TokenErrorMessage.ACCESS_TOKEN_INVALID);
            }
        } catch (ExpiredJwtException e) {
            log.debug("AccessToken is expired: {}, error: {}.", accessToken, e);
            throw new CredentialsTimeoutException(TokenErrorMessage.ACCESS_TOKEN_EXPIRED);
        } catch (Exception e) {
            log.debug("AccessToken is invalid: {}, error: {}.", accessToken, e);
            throw new CredentialsInvalidException(TokenErrorMessage.ACCESS_TOKEN_INVALID);
        }
    }

    @Override
    public Map<String, Object> parseRefreshToken(String refreshToken) {
        if (StringUtils.isEmpty(refreshToken) || "".equals(refreshToken.trim())) {
            throw new CredentialsNotFoundException(TokenErrorMessage.REFRESH_TOKEN_MISSING);
        }
        String secret = jwtTokenProperties.getSecret();
        try {
            Claims body = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(refreshToken.replace(jwtTokenProperties.getType() + " ", ""))
                    .getBody();
            if (Objects.equals(body.get(TOKEN_TYPE_KEY), REFRESH_TYPE_VALUE)) {
                return body;
            } else {
                throw new CredentialsInvalidException(TokenErrorMessage.REFRESH_TOKEN_INVALID);
            }
        } catch (ExpiredJwtException e) {
            log.debug("RefreshToken is expired: {}, error: {}.", refreshToken, e);
            throw new CredentialsTimeoutException(TokenErrorMessage.REFRESH_TOKEN_EXPIRED);
        } catch (Exception e) {
            log.debug("RefreshToken is invalid: {}, error: {}.", refreshToken, e);
            throw new CredentialsInvalidException(TokenErrorMessage.REFRESH_TOKEN_INVALID);
        }
    }

    /**
     * 生成访问令牌
     *
     * @param payload 令牌中包含的数据
     * @return 访问令牌
     */
    private String createAccessToken(Map<String, Object> payload, Token token) {
        payload.put(TOKEN_TYPE_KEY, ACCESS_TYPE_VALUE);
        Long tokenId = keyGenerator.generateKey();
        token.setRefreshTokenId(tokenId);
        return generateToken(payload, tokenProperties.getExpiresIn(), tokenId);
    }

    /**
     * 生成刷新令牌
     *
     * @param payload 令牌中包含的数据
     * @return 刷新令牌
     */
    private String createRefreshToken(Map<String, Object> payload, Token token) {
        payload.put(TOKEN_TYPE_KEY, REFRESH_TYPE_VALUE);
        Long tokenId = keyGenerator.generateKey();
        token.setAccessTokenId(tokenId);
        return generateToken(payload, tokenProperties.getRefreshExpiresIn(), tokenId);
    }

    /**
     * 创建jwt
     *
     * @param payload     jwt中载荷
     * @param expiresTime 到期时间
     * @return 令牌
     */
    private String generateToken(Map<String, Object> payload, long expiresTime, Long tokenId) {

        String secret = jwtTokenProperties.getSecret();
        SignatureAlgorithm algorithm = SignatureAlgorithm.forName(jwtTokenProperties.getAlgorithm());
        long now = System.currentTimeMillis();
        Date expTime = new Date(now + 1000 * expiresTime);
        return jwtTokenProperties.getType() + " " + Jwts.builder()
                .setId(tokenId.toString())
                .setClaims(payload)
                .setExpiration(expTime)
                .signWith(algorithm, secret)
                .compact();
    }
}

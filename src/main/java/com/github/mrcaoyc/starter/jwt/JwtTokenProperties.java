package com.github.mrcaoyc.starter.jwt;

import com.github.mrcaoyc.security.TokenProperties;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author CaoYongCheng
 */
@Data
@ConfigurationProperties(prefix = "security.jwt")
@EqualsAndHashCode
public class JwtTokenProperties extends TokenProperties {
    /**
     * 令牌签名密匙
     */
    private String secret = "7b5b71e2a4dbabed1f24659c7d2b633f";

    /**
     * token类型
     */
    private String type = "Bearer";

    /**
     * @see SignatureAlgorithm
     * 加密算法
     */
    private String algorithm = "HS256";
}

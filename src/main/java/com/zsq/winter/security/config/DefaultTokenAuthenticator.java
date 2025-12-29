package com.zsq.winter.security.config;

import com.zsq.winter.security.model.ValidateToken;

import java.util.ArrayList;

/**
 * 默认的Token认证器（仅用于开发环境）
 * 生产环境中应该提供自己的TokenAuthenticator实现
 */
public class DefaultTokenAuthenticator implements TokenAuthenticator {
    @Override
    public AuthResult authenticate(String token) {
        // 开发环境的简单实现：假设token格式为 "user:userId"
        if (token == null || token.trim().isEmpty()) {
            return AuthResult.failure("Token不能为空");
        }
        if (token.startsWith("DefaultTokenAuthenticator")){
            ValidateToken validateToken = ValidateToken.builder()
                    .roles(new ArrayList<>())
                    .permissions(new ArrayList<>())
                    .userId(666666L)
                    .userName("DefaultTokenAuthenticator------test")
                    .valid(true)
                    .build();
            return AuthResult.success(validateToken);
        }
        return AuthResult.failure("Token错误");
    }
}
    
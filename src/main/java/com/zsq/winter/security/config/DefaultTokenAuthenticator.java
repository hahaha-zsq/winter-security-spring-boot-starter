package com.zsq.winter.security.config;

import com.zsq.winter.security.model.ValidateToken;

import java.util.ArrayList;

/**
 * 默认的Token认证器（仅用于开发环境）
 * 
 * 这是一个简单的Token认证实现，仅用于开发和测试环境。
 * 生产环境中必须提供自定义的TokenAuthenticator实现，包含真实的JWT解析和验证逻辑。
 * 
 * 功能说明：
 * 1. 提供基础的Token格式验证
 * 2. 返回模拟的用户信息用于开发测试
 * 3. 在启动时会输出警告信息提醒开发者替换为生产实现
 * 
 * @author dandandiaoming
 */
public class DefaultTokenAuthenticator implements TokenAuthenticator {
    
    /**
     * 验证Token并返回认证结果
     * 
     * 这是一个简化的开发环境实现：
     * 1. 检查Token是否为空
     * 2. 如果Token以"DefaultTokenAuthenticator"开头，则认为是有效的测试Token
     * 3. 返回模拟的用户信息用于开发测试
     * 
     * 生产环境实现建议：
     * - 使用JWT库解析Token
     * - 验证Token签名和有效期
     * - 从Token中提取真实的用户信息
     * - 查询数据库获取用户角色和权限
     * 
     * @param token 待验证的Token字符串
     * @return 认证结果，包含用户信息或错误信息
     */
    @Override
    public AuthResult authenticate(String token) {
        // 基础验证：检查Token是否为空
        if (token == null || token.trim().isEmpty()) {
            return AuthResult.failure("Token不能为空");
        }
        
        // 开发环境的简单验证逻辑
        if (token.startsWith("DefaultTokenAuthenticator")){
            // 构建模拟的用户验证信息
            ValidateToken validateToken = ValidateToken.builder()
                    .roles(new ArrayList<>())           // 空角色列表
                    .permissions(new ArrayList<>())     // 空权限列表
                    .userId(666666L)                    // 测试用户ID
                    .userName("DefaultTokenAuthenticator------test")  // 测试用户名
                    .valid(true)                        // 标记为有效
                    .build();
            return AuthResult.success(validateToken);
        }
        
        // Token格式不正确
        return AuthResult.failure("Token格式错误");
    }
}
    
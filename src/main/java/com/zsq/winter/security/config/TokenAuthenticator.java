package com.zsq.winter.security.config;

import com.zsq.winter.security.model.ValidateToken;
import lombok.Getter;
import org.springframework.util.ObjectUtils;

/**
 * Token认证器接口
 * 
 * 定义Token验证的标准接口，使用者需要实现此接口来提供具体的Token验证逻辑。
 * 支持各种Token类型：JWT、OAuth2、自定义Token等。
 * 
 * 设计理念：
 * 1. 接口职责单一，只负责Token验证
 * 2. 返回结果包含详细的用户信息和权限数据
 * 3. 支持灵活的错误处理和异常情况
 * 
 * 使用示例：
 * <pre>
 * {@code
 * @Component
 * public class JwtTokenAuthenticator implements TokenAuthenticator {
 *     
 *     @Override
 *     public AuthResult authenticate(String token) {
 *         try {
 *             // 解析JWT Token
 *             Claims claims = Jwts.parser()
 *                 .setSigningKey(secretKey)
 *                 .parseClaimsJws(token)
 *                 .getBody();
 *             
 *             // 构建用户验证信息
 *             ValidateToken validateToken = ValidateToken.builder()
 *                 .userId(Long.valueOf(claims.getSubject()))
 *                 .userName(claims.get("username", String.class))
 *                 .roles(claims.get("roles", List.class))
 *                 .permissions(claims.get("permissions", List.class))
 *                 .valid(true)
 *                 .build();
 *             
 *             return AuthResult.success(validateToken);
 *         } catch (Exception e) {
 *             return AuthResult.failure("Token验证失败: " + e.getMessage());
 *         }
 *     }
 * }
 * }
 * </pre>
 * 
 * @author dandandiaoming
 */
@FunctionalInterface
public interface TokenAuthenticator {

    /**
     * 验证Token并返回认证结果
     * 
     * 实现者需要在此方法中完成以下工作：
     * 1. 验证Token的格式和签名
     * 2. 检查Token的有效期
     * 3. 解析Token中的用户信息
     * 4. 查询用户的角色和权限信息
     * 5. 构建并返回验证结果
     * 
     * @param token 客户端提供的认证令牌（通常是JWT格式）
     * @return 认证结果，包含是否成功、用户信息、角色权限或错误信息
     */
    AuthResult authenticate(String token);

    /**
     * Token认证结果封装类
     * 
     * 用于封装Token验证的结果信息，包括：
     * 1. 验证是否成功的标识
     * 2. 验证成功时的用户详细信息
     * 3. 验证失败时的错误描述信息
     */
    @Getter
    class AuthResult {
        
        /**
         * 认证是否成功
         * -- GETTER --
         *  判断认证是否成功

         */
        private final boolean success;

        /**
         * 验证成功的用户数据
         * 包含用户ID、用户名、角色列表、权限列表等完整信息
         */
        private final ValidateToken data;
        
        /**
         * 错误信息
         * 当认证失败时，此字段包含具体的失败原因描述
         * -- GETTER --
         *  获取错误信息
         */
        private final String errorMessage;

        /**
         * 私有构造函数
         * 
         * @param success 认证是否成功
         * @param data 认证成功时的用户数据
         * @param errorMessage 认证失败时的错误信息
         */
        private AuthResult(boolean success, ValidateToken data, String errorMessage) {
            this.success = success;
            this.data = data;
            this.errorMessage = errorMessage;
        }

        /**
         * 创建认证成功的结果
         * 
         * @param data 验证成功的用户数据，不能为空
         * @return 认证成功的结果对象
         * @throws IllegalArgumentException 当用户数据为空时抛出
         */
        public static AuthResult success(ValidateToken data) {
            if (ObjectUtils.isEmpty(data)) {
                throw new IllegalArgumentException("验证成功时用户数据不能为空");
            }
            return new AuthResult(true, data, null);
        }

        /**
         * 创建认证失败的结果
         * 
         * @param errorMessage 失败原因描述，建议提供具体的错误信息
         * @return 认证失败的结果对象
         */
        public static AuthResult failure(String errorMessage) {
            return new AuthResult(false, null, errorMessage);
        }

    }
}

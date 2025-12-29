package com.zsq.winter.security.config;

import com.zsq.winter.security.constants.SecurityConstants;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 安全模块配置属性类
 * <p>
 * 功能说明：
 * 1. 统一管理安全模块的配置项，支持通过application.yml进行配置
 * 2. 提供URL白名单配置支持，实现灵活的访问控制
 * 3. 支持配置项的默认值设置，确保模块的开箱即用特性
 * <p>
 * 设计目的：
 * - 解决硬编码配置的问题，提高配置的灵活性和可维护性
 * - 支持不同环境的差异化配置（开发、测试、生产）
 * - 提供配置项的类型安全和IDE智能提示支持
 * <p>
 * 配置前缀：winter.security
 * 
 */
@Data
@ConfigurationProperties(prefix ="winter.security")
public class SecurityProperties {

    /**
     * 白名单相关配置
     */
    private Whitelist whitelist = new Whitelist();
    /**
     * 用户ID请求头 - 网关传递用户唯一标识
     */
    private String userIdHeader = SecurityConstants.USER_ID_HEADER;

    /**
     * 用户名请求头 - 网关传递用户登录名
     */
    private String usernameHeader = SecurityConstants.USERNAME_HEADER;

    /**
     * 用户角色请求头 - 网关传递用户角色列表（逗号分隔）
     */
    private String rolesHeader = SecurityConstants.ROLES_HEADER;

    /**
     * 用户权限请求头 - 网关传递用户权限列表（逗号分隔）
     */
    private String permissionsHeader = SecurityConstants.PERMISSIONS_HEADER;

    /**
     * JWT认证头 - 标准的Authorization头，用于直连认证
     */
    private String authorizationHeader = SecurityConstants.AUTHORIZATION_HEADER;

    /**
     * JWT前缀 - Bearer token的标准前缀
     */
    private String bearerPrefix = SecurityConstants.BEARER_PREFIX;

    /**
     * 网关角色和权限分隔符 - 用于解析网关传递的角色和权限列表
     */
    private String gatewayRoleAndPermissionSeparator = SecurityConstants.COMMA_SEPARATOR;
    /**
     * 白名单相关配置
     */
    @Data
    public static class Whitelist {
        /**
         * URL白名单路径列表
         * 这些路径不需要进行身份认证，可以直接访问
         */
        private List<String> urls = Arrays.asList(
            // 系统监控和健康检查
            "/actuator/**",
            "/health",
            "/info",
            
            // 静态资源
            "/favicon.ico",
            "/static/**",
            "/public/**",
            "/webjars/**",
            
            // API文档（开发环境）
            "/swagger-ui/**",
            "/swagger-resources/**",
            "/v2/api-docs",
            "/v3/api-docs/**",
            
            // 认证相关接口
            "/auth/login",
            "/auth/register",
            "/auth/logout",
            "/auth/refresh",
            "/auth/captcha",
            
            // 错误处理
            "/error"
        );
    }
}
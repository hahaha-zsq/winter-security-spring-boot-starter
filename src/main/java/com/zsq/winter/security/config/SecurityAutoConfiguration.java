package com.zsq.winter.security.config;


import com.zsq.winter.security.filter.JwtAuthenticationFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * 安全模块自动配置类
 * 
 * 功能说明：
 * 1. 提供Spring Boot自动装配功能，实现"开箱即用"的安全认证
 * 2. 自动配置JWT认证过滤器、认证拦截器、链路追踪拦截器等核心组件
 * 3. 支持条件化配置，可通过配置文件灵活控制组件的启用/禁用
 * 
 * 设计目的：
 * - 解决微服务架构中安全认证配置复杂、重复的问题
 * - 提供统一的安全认证标准，确保各服务间认证机制的一致性
 * - 支持双路径认证：网关路径（从请求头获取用户信息）和直连路径（JWT token验证）
 * - 集成链路追踪功能，便于分布式系统的问题排查和性能监控
 * 
 * 条件注解说明：
 * - @ConditionalOnClass：只有在类路径中存在Spring Security相关类时才生效
 * - @ConditionalOnProperty：通过zt.security.enabled配置项控制是否启用（默认启用）
 *
 * @author zsq
 */
@Slf4j
@Configuration
@ConditionalOnClass({EnableWebSecurity.class, EnableGlobalMethodSecurity.class})
@EnableConfigurationProperties(SecurityProperties.class)
@Import({SecurityConfig.class})//把 SecurityConfig 这个配置类“手动导入”到当前 Spring 容器中，等价于：让 Spring 启动时加载并生效 SecurityConfig 里的所有 Bean 定义
public class SecurityAutoConfiguration {


    /**
     * 创建默认的Token认证器（仅用于开发环境）
     * <p>
     * 注入条件：
     * - winter-netty.enable-server=true（默认为true）
     * - winter-netty.server.websocket.enabled=true（默认为false）
     * - 容器中不存在TokenAuthenticator类型的Bean
     * <p>
     * 默认实现提供基础的Token验证功能，生产环境建议提供自定义实现。
     * 自定义实现需要实现TokenAuthenticator接口，提供以下功能：
     * - Token有效性验证
     * - 用户身份解析
     * - 权限检查等
     *
     * @return 默认Token认证器实例
     */
    @Bean
    @ConditionalOnMissingBean(TokenAuthenticator.class)
    public TokenAuthenticator defaultTokenAuthenticator() {
        log.warn("未配置自定义 TokenAuthenticator，使用默认实现（仅适用于开发环境）");
        return new DefaultTokenAuthenticator();
    }

    /**
     * 自动配置JWT认证过滤器
     * 
     * 功能说明：
     * - 处理HTTP请求的JWT认证逻辑
     * - 支持双路径认证：网关路径和直连路径
     * - 自动将认证信息设置到Spring Security上下文中
     * 
     * 条件说明：
     * - @ConditionalOnMissingBean：只有在容器中不存在该Bean时才创建，避免重复配置
     * 
     * @param tokenAuthenticator Token认证器，用于验证用户身份
     * @return JWT认证过滤器实例
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(TokenAuthenticator tokenAuthenticator,SecurityProperties securityProperties) {
        log.info("自动配置 JwtAuthenticationFilter");
        return new JwtAuthenticationFilter(tokenAuthenticator,securityProperties);
    }


}
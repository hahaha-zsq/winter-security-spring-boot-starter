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
 * 提供Spring Boot自动装配功能，实现开箱即用的安全认证
 * 支持双路径认证：网关路径（从请求头获取用户信息）和直连路径（JWT token验证）
 * 
 * @author dandandiaoming
 */
@Slf4j
@Configuration
@ConditionalOnClass({EnableWebSecurity.class, EnableGlobalMethodSecurity.class})
@EnableConfigurationProperties(SecurityProperties.class)
@Import({SecurityConfig.class})
public class SecurityAutoConfiguration {

    /**
     * 创建默认的Token认证器（仅用于开发环境）
     * 
     * 生产环境必须提供自定义实现，实现TokenAuthenticator接口
     * 自定义实现需要提供：Token有效性验证、用户身份解析、权限检查等功能
     */
    @Bean
    @ConditionalOnMissingBean(TokenAuthenticator.class)
    public TokenAuthenticator defaultTokenAuthenticator() {
        log.warn("==================== 安全警告 ====================");
        log.warn("未配置自定义 TokenAuthenticator，使用默认实现");
        log.warn("默认实现仅适用于开发环境，生产环境必须提供自定义实现");
        log.warn("请实现 TokenAuthenticator 接口并注册为 Spring Bean");
        log.warn("===============================================");
        return new DefaultTokenAuthenticator();
    }

    /**
     * 自动配置JWT认证过滤器
     * 处理HTTP请求的JWT认证逻辑，支持双路径认证
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(TokenAuthenticator tokenAuthenticator, 
                                                           SecurityProperties securityProperties) {
        log.info("自动配置 JwtAuthenticationFilter");
        return new JwtAuthenticationFilter(tokenAuthenticator, securityProperties);
    }
}

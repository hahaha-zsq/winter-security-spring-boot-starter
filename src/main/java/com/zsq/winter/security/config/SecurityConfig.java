package com.zsq.winter.security.config;

import com.zsq.winter.security.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Spring Security配置类 - 安全框架核心配置中心
 * <p>
 * 【核心功能】
 * 1. 配置Spring Security安全策略，实现JWT无状态认证
 * 2. 启用方法级权限校验，支持多种权限注解
 * 3. 集成自定义JWT认证过滤器，实现双路径认证
 * 4. 统一管理拦截器配置，避免配置分散
 * 5. 提供链路追踪和认证上下文管理
 * <p>
 * 【设计原理】
 * 1. 继承WebSecurityConfigurerAdapter：自定义Spring Security配置
 * 2. 实现WebMvcConfigurer：统一管理Spring MVC拦截器
 * 3. 无状态设计：禁用Session，使用JWT进行身份验证
 * 4. 方法级权限：通过注解实现细粒度权限控制
 * 5. 过滤器链：自定义JWT过滤器集成到Spring Security过滤器链
 * <p>
 * 【解决的业务问题】
 * 1. 微服务认证：在分布式架构中实现统一的身份认证
 * 2. 权限控制：提供灵活的方法级权限校验机制
 * 3. 性能优化：无状态JWT避免Session存储开销
 * 4. 链路追踪：集成分布式链路追踪，便于问题排查
 * 5. 上下文管理：确保认证上下文的正确传递和清理
 * <p>
 * 【与其他模块的交互】
 * 1. JwtAuthenticationFilter：集成JWT认证过滤器，处理认证逻辑
 * 2. AuthenticationInterceptor：管理认证上下文生命周期
 * 3. TraceInterceptor：提供链路追踪功能
 * 4. Spring Security：集成到Spring Security框架体系
 * 5. 业务Controller：通过权限注解控制访问权限
 * <p>
 * 【权限注解支持】
 * - @PreAuthorize/@PostAuthorize：方法执行前后的权限校验
 * - @Secured：基于角色的简单权限校验
 * - @RolesAllowed：JSR-250标准的角色权限校验
 * <p>
 * 【安全策略】
 * - 禁用CSRF：适用于无状态API
 * - 禁用Session：使用JWT无状态认证
 * - 禁用默认登录页：适用于前后端分离架构
 * - 自定义过滤器：集成JWT认证逻辑
 *
 * @author zsq
 */
// Spring配置注解：标识这是一个配置类，Spring会自动扫描并加载
@Configuration
// 启用Web安全：激活Spring Security的Web安全功能
@EnableWebSecurity
// Lombok注解：自动生成包含所有final字段的构造函数，用于依赖注入
@RequiredArgsConstructor
// 启用全局方法安全：支持多种权限注解
// prePostEnabled = true：启用@PreAuthorize和@PostAuthorize注解
// securedEnabled = true：启用@Secured注解  
// jsr250Enabled = true：启用@RolesAllowed注解（JSR-250标准）
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter implements WebMvcConfigurer {
    /**
     * JWT认证过滤器 - 核心认证组件
     * <p>
     * 【依赖注入】
     * 通过@RequiredArgsConstructor自动注入，确保过滤器在配置类中可用
     * <p>
     * 【作用说明】
     * 负责处理JWT认证逻辑，支持网关认证和直接JWT认证双路径
     * <p>
     * 【集成方式】
     * 在configure(HttpSecurity)方法中添加到Spring Security过滤器链
     */
    final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * 安全配置属性 - 通过依赖注入获取
     * <p>
     * 【依赖注入】
     * 通过@RequiredArgsConstructor自动注入，由SecurityAutoConfiguration自动配置
     * <p>
     * 【配置来源】
     * 从application.yml中读取zt.security前缀的配置项
     * <p>
     * 【设计优势】
     * 1. 外部化配置：支持通过配置文件灵活调整安全策略
     * 2. 环境隔离：不同环境可以使用不同的安全配置
     * 3. 动态调整：无需修改代码即可调整白名单等配置
     */
    final SecurityProperties securityProperties;


    /**
     * 配置HTTP安全策略 - Spring Security核心配置方法
     * <p>
     * 【方法作用】
     * 重写WebSecurityConfigurerAdapter的configure方法，自定义安全配置
     * <p>
     * 【配置策略】
     * 1. 无状态认证：禁用Session，使用JWT进行身份验证
     * 2. 禁用不必要功能：关闭CSRF、默认登录页、HTTP Basic认证
     * 3. 宽松授权策略：允许所有请求通过，权限校验交给方法级注解
     * 4. 自定义过滤器：集成JWT认证过滤器到过滤器链
     * <p>
     * 【设计考虑】
     * 1. 前后端分离：禁用传统的表单登录和Session机制
     * 2. API优先：适配RESTful API的无状态特性
     * 3. 灵活权限：通过注解实现细粒度的权限控制
     * 4. 性能优化：减少不必要的安全检查开销
     * <p>
     * 【过滤器顺序】
     * JWT过滤器位于UsernamePasswordAuthenticationFilter之前，
     * 确保在标准认证流程之前完成JWT认证
     *
     * @param http HttpSecurity配置对象，用于构建安全配置
     * @throws Exception 配置过程中可能抛出的异常
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // 禁用CSRF保护 - 适用于无状态API，前后端分离架构
                .csrf().disable()
                // 配置Session管理策略 - 设置为无状态，不创建和使用Session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // 配置请求授权规则
                .authorizeRequests()
                //以下接口不需要认证 - 从配置文件读取白名单
                .antMatchers(securityProperties.getWhitelist().getUrls().toArray(new String[0])).permitAll()
                // 除上面外的所有请求全部不需要认证即可访问
                //.anyRequest().permitAll();
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated()
                .and()
                // 禁用默认登录页面 - 适用于前后端分离，不需要服务端渲染登录页
                .formLogin().disable()
                // 禁用HTTP Basic认证 - 使用JWT替代Basic认证
                .httpBasic().disable()
                // 添加自定义JWT认证过滤器 - 在标准用户名密码认证过滤器之前执行
                // 确保JWT认证逻辑优先处理，支持网关认证和直接JWT认证
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
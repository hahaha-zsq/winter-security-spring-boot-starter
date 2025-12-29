package com.zsq.winter.security.context;

import com.alibaba.ttl.TransmittableThreadLocal;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

/**
 * 登录上下文持有者 - 基于TTL的跨线程用户信息管理器
 * 
 * 核心功能：
 * 1. 使用TransmittableThreadLocal实现跨线程的用户上下文传递
 * 2. 提供线程安全的用户信息存储和访问
 * 3. 支持异步任务和线程池场景下的上下文传递
 * 4. 提供便捷的用户信息访问方法
 * 
 * 注意：此类与Spring Security的SecurityContextHolder配合使用
 * 
 * @author zsq
 */
@Slf4j
public class WinterSecurityContextHolder {
    
    /**
     * TTL变量，存储当前线程的用户上下文信息，支持跨线程传递
     */
    private static final TransmittableThreadLocal<LoginContext> CONTEXT_HOLDER = new TransmittableThreadLocal<>();

    /**
     * 设置登录上下文
     */
    public static void setContext(String userId, String username, List<String> roles, List<String> permissions) {
        if (userId == null || username == null) {
            log.warn("尝试设置无效的登录上下文: userId={}, username={}", userId, username);
            return;
        }
        
        LoginContext context = new LoginContext();
        context.setUserId(userId);
        context.setUsername(username);
        context.setRoles(roles);
        context.setPermissions(permissions);
        context.setLoginTime(System.currentTimeMillis());
        
        CONTEXT_HOLDER.set(context);
        log.debug("设置登录上下文: userId={}, username={}", userId, username);
    }

    /**
     * 获取完整的登录上下文对象
     */
    public static LoginContext getContext() {
        return CONTEXT_HOLDER.get();
    }

    /**
     * 获取当前登录用户ID
     */
    public static String getUserId() {
        LoginContext context = getContext();
        return context != null ? context.getUserId() : null;
    }

    /**
     * 获取当前用户ID（Long类型）
     */
    public static Long getUserIdAsLong() {
        String userId = getUserId();
        if (userId != null) {
            try {
                return Long.valueOf(userId);
            } catch (NumberFormatException e) {
                log.warn("用户ID格式错误: {}", userId);
            }
        }
        return null;
    }

    /**
     * 获取当前登录用户名
     */
    public static String getUsername() {
        LoginContext context = getContext();
        return context != null ? context.getUsername() : null;
    }

    /**
     * 获取当前用户的角色列表
     */
    public static List<String> getRoles() {
        LoginContext context = getContext();
        return context != null ? context.getRoles() : null;
    }

    /**
     * 获取当前用户的权限列表
     */
    public static List<String> getPermissions() {
        LoginContext context = getContext();
        return context != null ? context.getPermissions() : null;
    }

    /**
     * 获取用户登录时间戳
     */
    public static Long getLoginTime() {
        LoginContext context = getContext();
        return context != null ? context.getLoginTime() : null;
    }

    /**
     * 检查当前用户是否具有指定角色
     */
    public static boolean hasRole(String role) {
        List<String> roles = getRoles();
        return roles != null && roles.contains(role);
    }

    /**
     * 检查当前用户是否具有指定权限
     */
    public static boolean hasPermission(String permission) {
        List<String> permissions = getPermissions();
        return permissions != null && permissions.contains(permission);
    }

    /**
     * 清除当前线程的登录上下文
     * 注意：此方法会在JwtAuthenticationFilter的finally块中自动调用
     */
    public static void clear() {
        LoginContext context = getContext();
        if (context != null) {
            log.debug("清除登录上下文: userId={}", context.getUserId());
        }
        CONTEXT_HOLDER.remove();
    }

    /**
     * 登录上下文数据类
     */
    @Data
    public static class LoginContext {
        private String userId;
        private String username;
        private List<String> roles;
        private List<String> permissions;
        private Long loginTime;
    }
}
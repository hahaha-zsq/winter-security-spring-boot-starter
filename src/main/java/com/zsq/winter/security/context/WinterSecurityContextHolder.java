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
 * 技术特点：
 * - 基于阿里巴巴TTL库，解决线程池复用导致的上下文丢失问题
 * - 与Spring Security的SecurityContextHolder配合使用
 * - 提供类型安全的用户信息访问接口
 * - 自动管理上下文生命周期，防止内存泄漏
 * 
 * @author dandandiaoming
 */
@Slf4j
public class WinterSecurityContextHolder {
    
    /**
     * TTL变量，存储当前线程的用户上下文信息，支持跨线程传递
     */
    private static final TransmittableThreadLocal<LoginContext> CONTEXT_HOLDER = new TransmittableThreadLocal<>();

    /**
     * 设置登录上下文
     * 
     * 将用户的认证信息设置到当前线程的上下文中，支持跨线程传递。
     * 
     * @param userId 用户唯一标识，不能为空
     * @param username 用户登录名，不能为空  
     * @param roles 用户角色列表，可以为空
     * @param permissions 用户权限列表，可以为空
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
     * 
     * @return 当前线程的登录上下文，如果未设置则返回null
     */
    public static LoginContext getContext() {
        return CONTEXT_HOLDER.get();
    }

    /**
     * 获取当前登录用户ID
     * 
     * @return 用户ID字符串，如果未登录则返回null
     */
    public static String getUserId() {
        LoginContext context = getContext();
        return context != null ? context.getUserId() : null;
    }

    /**
     * 获取当前用户ID（Long类型）
     * 
     * 将字符串类型的用户ID转换为Long类型，便于数据库操作
     * 
     * @return 用户ID的Long值，如果未登录或转换失败则返回null
     */
    public static Long getUserIdAsLong() {
        String userId = getUserId();
        if (userId != null) {
            try {
                return Long.valueOf(userId);
            } catch (NumberFormatException e) {
                log.warn("用户ID格式错误，无法转换为Long类型: {}", userId);
            }
        }
        return null;
    }

    /**
     * 获取当前登录用户名
     * 
     * @return 用户登录名，如果未登录则返回null
     */
    public static String getUsername() {
        LoginContext context = getContext();
        return context != null ? context.getUsername() : null;
    }

    /**
     * 获取当前用户的角色列表
     * 
     * @return 用户角色列表，如果未登录或无角色则返回null
     */
    public static List<String> getRoles() {
        LoginContext context = getContext();
        return context != null ? context.getRoles() : null;
    }

    /**
     * 获取当前用户的权限列表
     * 
     * @return 用户权限列表，如果未登录或无权限则返回null
     */
    public static List<String> getPermissions() {
        LoginContext context = getContext();
        return context != null ? context.getPermissions() : null;
    }

    /**
     * 获取用户登录时间戳
     * 
     * @return 登录时间的毫秒时间戳，如果未登录则返回null
     */
    public static Long getLoginTime() {
        LoginContext context = getContext();
        return context != null ? context.getLoginTime() : null;
    }

    /**
     * 检查当前用户是否具有指定角色
     * 
     * @param role 要检查的角色名称
     * @return 如果用户具有该角色返回true，否则返回false
     */
    public static boolean hasRole(String role) {
        List<String> roles = getRoles();
        return roles != null && roles.contains(role);
    }

    /**
     * 检查当前用户是否具有指定权限
     * 
     * @param permission 要检查的权限名称
     * @return 如果用户具有该权限返回true，否则返回false
     */
    public static boolean hasPermission(String permission) {
        List<String> permissions = getPermissions();
        return permissions != null && permissions.contains(permission);
    }

    /**
     * 清除当前线程的登录上下文
     * 
     * 重要说明：
     * 1. 此方法会在JwtAuthenticationFilter的finally块中自动调用
     * 2. 手动调用时需要确保在合适的时机，避免影响正常的请求处理
     * 3. 清除操作是线程安全的，不会影响其他线程的上下文
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
     * 
     * 封装用户的登录信息，包括基本身份信息和权限数据
     * 使用Lombok的@Data注解自动生成getter/setter方法
     */
    @Data
    public static class LoginContext {
        /** 用户唯一标识 */
        private String userId;
        /** 用户登录名 */
        private String username;
        /** 用户角色列表 */
        private List<String> roles;
        /** 用户权限列表 */
        private List<String> permissions;
        /** 登录时间戳（毫秒） */
        private Long loginTime;
    }
}
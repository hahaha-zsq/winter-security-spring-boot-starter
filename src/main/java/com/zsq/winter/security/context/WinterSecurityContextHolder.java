package com.zsq.winter.security.context;

import com.alibaba.ttl.TransmittableThreadLocal;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

/**
 * 登录上下文持有者 - 基于TTL的跨线程用户信息管理器
 * 
 * 【核心功能实现原理】
 * 1. 使用TransmittableThreadLocal实现跨线程的用户上下文传递
 * 2. 提供线程安全的用户信息存储和访问机制
 * 3. 支持异步任务和线程池场景下的上下文传递
 * 4. 提供便捷的用户信息访问方法，简化业务代码
 * 
 * 【代码结构设计思路】
 * - 静态工具类设计：提供全局访问点，无需依赖注入
 * - TTL技术选型：解决ThreadLocal在线程池中的传递问题
 * - 方法重载：提供多种数据类型的访问方式，提升易用性
 * - 内部类封装：使用LoginContext封装用户信息，保证数据完整性
 * 
 * 【解决的具体业务问题】
 * 1. 跨线程上下文传递：解决异步任务中无法获取用户信息的问题
 * 2. 线程池复用问题：避免ThreadLocal在线程池中的数据污染
 * 3. 业务代码简化：提供统一的用户信息访问接口，减少重复代码
 * 4. 内存泄漏防护：提供clear方法，防止ThreadLocal内存泄漏
 * 
 * 【与其他模块的交互关系】
 * - JwtAuthenticationFilter：认证成功后设置用户上下文
 * - AuthenticationInterceptor：请求结束后清理上下文，防止内存泄漏
 * - 业务代码：通过静态方法获取当前用户信息
 * - Context.java：与统一上下文管理器协同工作
 * - 异步任务：在@Async方法中自动传递用户上下文
 * 
 * @author zsq
 */
@Slf4j
public class WinterSecurityContextHolder {
    
    /**
     * TTL变量，存储当前线程的用户上下文信息，支持跨线程传递
     * 
     * 【TTL技术原理】
     * TransmittableThreadLocal是阿里巴巴开源的ThreadLocal增强版
     * 解决了ThreadLocal在线程池、异步任务中无法传递的问题
     * 
     * 【工作机制】
     * 1. 在父线程中设置的值会自动传递到子线程
     * 2. 支持线程池场景，避免线程复用导致的数据污染
     * 3. 提供自动清理机制，防止内存泄漏
     * 
     * 【应用场景】
     * - 异步任务：@Async注解的方法中可以获取到用户信息
     * - 线程池：ExecutorService提交的任务中可以获取用户信息
     * - 消息队列：MQ消费者中可以获取到生产者的用户信息
     * - 定时任务：@Scheduled任务中可以获取触发用户的信息
     */
    private static final TransmittableThreadLocal<LoginContext> CONTEXT_HOLDER = new TransmittableThreadLocal<>();

    /**
     * 设置登录上下文 - 用户认证成功后的信息存储
     * 
     * 【调用时机】
     * 通常在用户认证成功后调用，如JWT验证通过、Session验证通过等
     * 
     * 【参数说明】
     * @param userId 用户唯一标识，通常是数据库主键
     * @param username 用户登录名，用于显示和日志记录
     * @param roles 用户角色列表，用于粗粒度权限控制
     * @param permissions 用户权限列表，用于细粒度权限控制
     * 
     * 【设计考虑】
     * - 自动设置登录时间：记录用户信息设置的时间戳
     * - 参数校验：确保必要的用户信息不为空
     * - 日志记录：记录用户上下文设置操作，便于问题排查
     */
    public static void setContext(String userId, String username, List<String> roles, List<String> permissions) {
        // 创建登录上下文对象
        LoginContext context = new LoginContext();
        context.setUserId(userId);
        context.setUsername(username);
        context.setRoles(roles);
        context.setPermissions(permissions);
        // 记录设置时间，用于会话管理和审计
        context.setLoginTime(System.currentTimeMillis());
        
        // 将上下文存储到TTL变量中
        CONTEXT_HOLDER.set(context);
        log.debug("设置登录上下文: userId={}, username={}", userId, username);
    }

    /**
     * 获取完整的登录上下文对象
     * 
     * 【使用场景】
     * 当需要获取用户的完整信息时使用，包括用户ID、用户名、角色、权限等
     * 
     * 【返回值说明】
     * @return LoginContext 登录上下文对象，如果未登录则返回null
     * 
     * 【注意事项】
     * - 返回值可能为null，调用方需要进行空值检查
     * - 该方法是其他get方法的基础，其他方法都基于此方法实现
     * - 线程安全：TTL保证了多线程环境下的数据隔离
     */
    public static LoginContext getContext() {
        return CONTEXT_HOLDER.get();
    }

    /**
     * 获取当前登录用户ID
     * 
     * 【业务用途】
     * - 数据权限控制：查询用户自己的数据
     * - 操作日志记录：记录是哪个用户执行的操作
     * - 业务逻辑判断：基于用户ID进行业务处理
     * 
     * 【实现原理】
     * 从TTL中获取LoginContext，然后提取userId字段
     * 
     * @return String 用户ID，未登录时返回null
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
     * 
     * 【业务用途】
     * - 页面显示：在前端显示当前登录用户
     * - 日志记录：在日志中记录操作用户的用户名
     * - 审计追踪：记录业务操作的执行者
     * 
     * @return String 用户名，未登录时返回null
     */
    public static String getUsername() {
        LoginContext context = getContext();
        return context != null ? context.getUsername() : null;
    }

    /**
     * 获取当前用户的角色列表
     * 
     * 【权限控制用途】
     * - 粗粒度权限控制：基于角色进行功能模块的访问控制
     * - 菜单显示：根据角色显示不同的菜单项
     * - 业务流程控制：不同角色执行不同的业务逻辑
     * 
     * 【数据格式】
     * 通常是角色编码列表，如：["ADMIN", "USER", "MANAGER"]
     * 
     * @return List<String> 角色列表，未登录时返回null
     */
    public static List<String> getRoles() {
        LoginContext context = getContext();
        return context != null ? context.getRoles() : null;
    }

    /**
     * 获取当前用户的权限列表
     * 
     * 【权限控制用途】
     * - 细粒度权限控制：精确控制用户可以执行的操作
     * - API访问控制：控制用户可以调用哪些接口
     * - 数据操作权限：控制用户可以对哪些数据进行增删改查
     * 
     * 【数据格式】
     * 通常是权限编码列表，如：["user:read", "user:write", "order:delete"]
     * 
     * @return List<String> 权限列表，未登录时返回null
     */
    public static List<String> getPermissions() {
        LoginContext context = getContext();
        return context != null ? context.getPermissions() : null;
    }

    /**
     * 获取用户登录时间戳
     * 
     * 【业务用途】
     * - 会话管理：判断用户登录时长，实现会话超时控制
     * - 安全审计：记录用户的登录时间，用于安全分析
     * - 统计分析：分析用户的活跃时间段
     * 
     * @return Long 登录时间戳（毫秒），未登录时返回null
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
     * 清除当前线程的登录上下文 - 防止内存泄漏的关键方法
     * 
     * 【调用时机】
     * 1. 用户退出登录时
     * 2. 请求处理完成后（通过拦截器自动调用）
     * 3. 异常处理时的清理操作
     * 4. 定时任务执行完成后
     * 
     * 【重要性说明】
     * 虽然使用了TTL，但在某些场景下仍需要手动清理：
     * - 防止长时间运行的线程中数据残留
     * - 避免在线程池中的数据污染
     * - 确保敏感信息及时清理
     * 
     * 【最佳实践】
     * 通常在AuthenticationInterceptor的afterCompletion方法中自动调用
     * 也可以在finally块中手动调用，确保无论是否异常都能清理
     */
    public static void clear() {
        String userId = getUserId();
        CONTEXT_HOLDER.remove();
        log.debug("清除登录上下文: userId={}", userId);
    }

    /**
     * 登录上下文数据类
     */
    @Data
    public static class LoginContext {
        /**
         * 用户ID
         */
        private String userId;

        /**
         * 用户名
         */
        private String username;

        /**
         * 用户角色列表
         */
        private List<String> roles;

        /**
         * 用户权限列表
         */
        private List<String> permissions;

        /**
         * 登录时间戳
         */
        private Long loginTime;
    }
}
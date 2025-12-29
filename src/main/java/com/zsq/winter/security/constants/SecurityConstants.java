package com.zsq.winter.security.constants;

/**
 * 安全模块统一常量配置类
 * 
 * 功能说明：
 * 1. 统一管理安全模块中的所有常量，避免魔法字符的硬编码
 * 2. 提供清晰的常量分类和命名规范，提高代码可维护性
 * 3. 支持IDE智能提示和重构，降低维护成本
 * 
 * 设计原则：
 * - 按功能模块分组管理常量
 * - 使用有意义的常量名称，避免缩写
 * - 提供详细的注释说明，便于理解和维护
 * - 采用final class设计，防止被继承和实例化
 * 
 * @author dandandiaoming
 */
public final class SecurityConstants {

    // ==================== HTTP 头名称常量 ====================
    
    /**
     * HTTP头名称 - 流量标签
     * 用于标识请求的流量类型，支持灰度发布和A/B测试
     */
    public static final String TRAFFIC_TAG_HEADER = "X-Traffic-Tag";
    
    /**
     * HTTP头名称 - 链路追踪ID
     * 用于分布式链路追踪，标识一次完整的请求链路
     */
    public static final String TRACE_ID_HEADER = "X-Trace-Id";
    
    /**
     * HTTP头名称 - 用户ID
     * 网关传递用户唯一标识
     */
    public static final String USER_ID_HEADER = "X-User-Id";
    
    /**
     * HTTP头名称 - 用户名
     * 网关传递用户登录名
     */
    public static final String USERNAME_HEADER = "X-Username";
    
    /**
     * HTTP头名称 - 用户角色
     * 网关传递用户角色列表（逗号分隔）
     */
    public static final String ROLES_HEADER = "X-User-Roles";
    
    /**
     * HTTP头名称 - 用户权限
     * 网关传递用户权限列表（逗号分隔）
     */
    public static final String PERMISSIONS_HEADER = "X-User-Permissions";
    
    /**
     * HTTP头名称 - JWT认证头
     * 标准的Authorization头，用于直连认证
     */
    public static final String AUTHORIZATION_HEADER = "Authorization";

    // ==================== JWT Token 相关常量 ====================
    
    /**
     * JWT Token前缀
     * Bearer token的标准前缀
     */
    public static final String BEARER_PREFIX = "Bearer ";

    // ==================== 上下文变量名称常量 ====================
    
    /**
     * 链路追踪ID变量名
     * 用于ThreadLocal和日志上下文中的变量名
     */
    public static final String TRACE_ID_KEY = "traceId";

    // ==================== 日志相关常量 ====================
    
    /**
     * TTL模式转换器名称
     * Log4j2插件中使用的转换器名称
     */
    public static final String TTL_CONVERTER_NAME = "ttl";
    
    /**
     * TTL模式转换器名称（大写）
     * Log4j2插件中使用的转换器名称（大写形式）
     */
    public static final String TTL_CONVERTER_NAME_UPPER = "TTL";
    
    /**
     * 默认占位符
     * 当上下文信息缺失时使用的默认值
     */
    public static final String DEFAULT_PLACEHOLDER = "-";

    // ==================== 分隔符常量 ====================
    
    /**
     * 逗号分隔符
     * 用于分割角色、权限等列表数据
     */
    public static final String COMMA_SEPARATOR = ",";
    
    /**
     * 连字符分隔符
     * 用于UUID等标识符的分隔
     */
    public static final String HYPHEN_SEPARATOR = "-";

    // ==================== 配置相关常量 ====================


    // ==================== URL路径常量 ====================
    
    /**
     * 系统监控和健康检查路径
     */
    public static final class SystemPaths {
        /** Actuator监控端点 */
        public static final String ACTUATOR = "/actuator/**";
        /** 健康检查端点 */
        public static final String HEALTH = "/health";
        /** 应用信息端点 */
        public static final String INFO = "/info";
        /** 网站图标 */
        public static final String FAVICON = "/favicon.ico";
        /** 错误处理端点 */
        public static final String ERROR = "/error";
    }
    
    /**
     * 静态资源路径
     */
    public static final class StaticPaths {
        /** 静态资源目录 */
        public static final String STATIC = "/static/**";
        /** 公共资源目录 */
        public static final String PUBLIC = "/public/**";
        /** WebJars资源 */
        public static final String WEBJARS = "/webjars/**";
    }
    
    /**
     * API文档相关路径
     */
    public static final class DocumentPaths {
        /** Swagger UI */
        public static final String SWAGGER_UI = "/swagger-ui/**";
        /** Swagger资源 */
        public static final String SWAGGER_RESOURCES = "/swagger-resources/**";
        /** API文档v2 */
        public static final String API_DOCS_V2 = "/v2/api-docs";
        /** API文档v3 */
        public static final String API_DOCS_V3 = "/v3/api-docs/**";
    }
    
    /**
     * 认证相关路径
     */
    public static final class AuthPaths {
        /** 用户登录 */
        public static final String LOGIN = "/auth/login";
        /** 用户注册 */
        public static final String REGISTER = "/auth/register";
        /** 用户登出 */
        public static final String LOGOUT = "/auth/logout";
        /** Token刷新 */
        public static final String REFRESH = "/auth/refresh";
        /** 验证码获取 */
        public static final String CAPTCHA = "/auth/captcha";
    }

    // ==================== 缓存相关常量 ====================
    
    /**
     * 缓存键前缀
     */
    public static final class CachePrefix {
        /** 用户信息缓存前缀 */
        public static final String USER_INFO = "user:info:";
        /** 用户权限缓存前缀 */
        public static final String USER_PERMISSION = "user:permission:";
        /** 用户角色缓存前缀 */
        public static final String USER_ROLE = "user:role:";
    }

    // ==================== 拦截器路径常量 ====================
    
    /**
     * 拦截器路径配置
     */
    public static final class InterceptorPaths {
        /** 拦截所有请求 */
        public static final String ALL_PATHS = "/**";
    }

    /**
     * 私有构造函数，防止实例化
     * 这是一个工具类，不应该被实例化
     */
    private SecurityConstants() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }
}
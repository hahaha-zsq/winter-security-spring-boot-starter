# Winter Security Spring Boot Starter

<div align="center">

[![Maven Central](https://img.shields.io/maven-central/v/io.github.hahaha-zsq/winter-security-spring-boot-starter.svg)](https://search.maven.org/artifact/io.github.hahaha-zsq/winter-security-spring-boot-starter)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-2.6.11-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Java](https://img.shields.io/badge/Java-1.8+-orange.svg)](https://www.oracle.com/java/)

一个开箱即用的 Spring Boot 安全认证启动器，支持 JWT 认证和微服务网关集成

[快速开始](#快速开始) • [功能特性](#功能特性) • [使用文档](#使用文档) • [示例代码](#示例代码)

</div>

---

## 📖 项目简介

**Winter Security Spring Boot Starter** 是一个轻量级、高性能的 Spring Security 认证授权解决方案，专为微服务架构设计。它提供了开箱即用的 JWT 认证功能，支持网关统一认证和服务直连认证两种模式，让开发者无需关心复杂的安全配置，专注于业务开发。

### 🎯 解决的问题

在微服务架构中，安全认证面临以下挑战：

- **重复配置**：每个微服务都需要配置相似的 Spring Security 代码
- **网关集成**：网关认证后，下游服务如何获取用户信息
- **直连访问**：开发调试时，如何绕过网关直接访问服务
- **上下文传递**：异步任务和线程池场景下，用户信息如何传递
- **权限控制**：如何优雅地实现方法级权限校验

本项目通过 Spring Boot Starter 机制，提供统一的解决方案，让这些问题迎刃而解。

---

## ✨ 功能特性

### 🔐 双路径认证

- **网关认证模式**：从 HTTP 请求头获取网关传递的用户信息（推荐生产环境）
- **JWT 直连模式**：解析 JWT Token 进行身份验证（适合开发调试）
- 自动识别认证方式，无需手动切换

### 🚀 开箱即用

- 零配置启动，引入依赖即可使用
- 自动装配 Spring Security 配置
- 内置合理的默认白名单（健康检查、静态资源、API 文档等）
- 支持自定义配置覆盖

### 🧵 跨线程上下文

- 基于阿里 TTL（TransmittableThreadLocal）实现
- 支持异步任务、线程池场景下的用户信息传递
- 自动清理上下文，防止内存泄漏

### 🎯 方法级权限

- 支持 `@PreAuthorize`、`@Secured`、`@RolesAllowed` 注解
- 提供便捷的权限检查工具类
- 与 Spring Security 无缝集成

### 🔧 高度可扩展

- 提供 `TokenAuthenticator` 接口，支持自定义 Token 验证逻辑
- 灵活的配置项，满足不同场景需求
- 支持自定义白名单、请求头名称等

---

## 🏗️ 技术架构

### 核心技术栈

| 技术 | 版本 | 说明 |
|------|------|------|
| Spring Boot | 2.6.11 | 基础框架 |
| Spring Security | 5.6.x | 安全认证框架 |
| Alibaba TTL | 2.14.5 | 跨线程上下文传递 |
| Lombok | - | 简化代码 |

### 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                      客户端请求                               │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │      JwtAuthenticationFilter          │
        │   （JWT 认证过滤器 - 核心入口）         │
        └───────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
                ▼                       ▼
    ┌─────────────────────┐   ┌─────────────────────┐
    │   网关认证模式        │   │   JWT 直连模式       │
    │ （从请求头获取）      │   │ （解析 JWT Token）   │
    └─────────────────────┘   └─────────────────────┘
                │                       │
                └───────────┬───────────┘
                            ▼
            ┌───────────────────────────────┐
            │    TokenAuthenticator         │
            │  （Token 验证器 - 可扩展）     │
            └───────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
                ▼                       ▼
    ┌─────────────────────┐   ┌─────────────────────┐
    │ SecurityContext     │   │ WinterSecurityContext│
    │ （Spring Security）  │   │ （自定义上下文）      │
    └─────────────────────┘   └─────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │      业务方法执行              │
            │  （支持 @PreAuthorize 等）     │
            └───────────────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │      自动清理上下文            │
            │  （防止内存泄漏）              │
            └───────────────────────────────┘
```

### 核心组件

#### 1. JwtAuthenticationFilter（认证过滤器）
- 拦截所有 HTTP 请求
- 识别认证方式（网关 or JWT）
- 设置 Spring Security 和自定义上下文
- 请求结束后自动清理上下文

#### 2. TokenAuthenticator（Token 验证器）
- 接口设计，支持自定义实现
- 负责 JWT Token 的解析和验证
- 返回用户身份信息

#### 3. WinterSecurityContextHolder（上下文持有者）
- 基于 TTL 实现跨线程传递
- 提供便捷的用户信息访问方法
- 支持角色和权限检查

#### 4. SecurityAutoConfiguration（自动配置）
- Spring Boot 自动装配入口
- 注册核心 Bean
- 加载配置属性

---

## 🚀 快速开始

### 1. 添加依赖

在项目的 `pom.xml` 中添加依赖：

```xml
<dependency>
    <groupId>io.github.hahaha-zsq</groupId>
    <artifactId>winter-security-spring-boot-starter</artifactId>
    <version>0.0.1</version>
</dependency>
```

### 2. 实现 TokenAuthenticator

创建自定义的 Token 验证器（生产环境必须）：

```java
@Component
public class JwtTokenAuthenticator implements TokenAuthenticator {
    
    @Autowired
    private AuthService authService; // 你的认证服务
    
    @Override
    public AuthResult authenticate(String token) {
        try {
            // 调用认证服务验证 Token
            ValidateToken result = authService.validateToken(token);
            
            if (result.getValid()) {
                return AuthResult.success(result);
            } else {
                return AuthResult.failure("Token 无效");
            }
        } catch (Exception e) {
            return AuthResult.failure("Token 验证失败: " + e.getMessage());
        }
    }
}
```

### 3. 配置文件（可选）

在 `application.yml` 中自定义配置：

```yaml
winter:
  security:
    # 白名单配置
    whitelist:
      urls:
        - /api/public/**
        - /auth/**
        - /actuator/**
    
    # 自定义请求头名称（可选）
    user-id-header: X-User-Id
    username-header: X-Username
    roles-header: X-User-Roles
    permissions-header: X-User-Permissions
```

### 4. 使用用户信息

在业务代码中获取当前用户信息：

```java
@RestController
@RequestMapping("/api/user")
public class UserController {
    
    @GetMapping("/info")
    public UserInfo getCurrentUser() {
        // 方式1：使用自定义上下文
        String userId = WinterSecurityContextHolder.getUserId();
        String username = WinterSecurityContextHolder.getUsername();
        List<String> roles = WinterSecurityContextHolder.getRoles();
        
        // 方式2：使用 Spring Security
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        
        return new UserInfo(userId, username, roles);
    }
    
    // 方法级权限控制
    @PreAuthorize("hasAuthority('user:delete')")
    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable Long id) {
        // 只有拥有 user:delete 权限的用户才能访问
    }
}
```

---

## 📚 使用文档

### 网关集成

网关需要在请求头中传递用户信息，推荐的请求头：

| 请求头 | 说明 | 示例 |
|--------|------|------|
| X-User-Id | 用户唯一标识 | 10001 |
| X-Username | 用户登录名 | zhangsan |
| X-User-Roles | 用户角色列表（逗号分隔） | admin,user |
| X-User-Permissions | 用户权限列表（逗号分隔） | user:read,user:write |

**重要提示**：网关必须移除客户端手动传递的这些请求头，防止伪造身份。

### JWT 直连认证

开发调试时，可以直接携带 JWT Token 访问服务：

```bash
curl -H "Authorization: Bearer <your-jwt-token>" \
     http://localhost:8080/api/user/info
```

### 白名单配置

默认白名单包括：

- `/actuator/**` - 健康检查和监控端点
- `/auth/**` - 认证相关接口
- `/swagger-ui/**` - API 文档
- `/error` - 错误处理

自定义白名单：

```yaml
winter:
  security:
    whitelist:
      urls:
        - /api/public/**
        - /health
        - /info
```

### 权限控制

支持多种权限注解：

```java
// 1. @PreAuthorize - 支持 SpEL 表达式
@PreAuthorize("hasAuthority('user:delete')")
public void deleteUser(Long id) { }

@PreAuthorize("hasRole('ADMIN')")
public void adminOnly() { }

@PreAuthorize("hasAnyAuthority('user:read', 'user:write')")
public void readOrWrite() { }

// 2. @Secured - 简单角色检查
@Secured("ROLE_ADMIN")
public void securedMethod() { }

// 3. @RolesAllowed - JSR-250 标准
@RolesAllowed({"ADMIN", "USER"})
public void jsr250Method() { }
```

### 异步任务支持

得益于 TTL，用户上下文可以自动传递到异步任务：

```java
@Service
public class AsyncService {
    
    @Async
    public void asyncTask() {
        // 异步任务中也能获取用户信息
        String userId = WinterSecurityContextHolder.getUserId();
        System.out.println("异步任务执行者: " + userId);
    }
}
```

---

## 💡 示例代码

### 完整的认证服务实现

```java
@Service
public class AuthServiceImpl implements TokenAuthenticator {
    
    @Value("${jwt.secret}")
    private String jwtSecret;
    
    @Autowired
    private UserService userService;
    
    @Override
    public AuthResult authenticate(String token) {
        try {
            // 1. 解析 JWT Token
            Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
            
            // 2. 提取用户信息
            Long userId = Long.valueOf(claims.getSubject());
            String username = claims.get("username", String.class);
            
            // 3. 查询用户权限（可选，也可以从 Token 中获取）
            User user = userService.getById(userId);
            
            // 4. 构造验证结果
            ValidateToken result = new ValidateToken();
            result.setValid(true);
            result.setUserId(userId);
            result.setUserName(username);
            result.setRoles(user.getRoles());
            result.setPermissions(user.getPermissions());
            
            return AuthResult.success(result);
            
        } catch (ExpiredJwtException e) {
            return AuthResult.failure("Token 已过期");
        } catch (Exception e) {
            return AuthResult.failure("Token 验证失败: " + e.getMessage());
        }
    }
}
```

### 网关配置示例（Spring Cloud Gateway）

```java
@Component
public class AuthGatewayFilter implements GlobalFilter, Ordered {
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 1. 验证 Token
        String token = extractToken(exchange.getRequest());
        UserInfo userInfo = validateToken(token);
        
        // 2. 添加用户信息到请求头
        ServerHttpRequest request = exchange.getRequest().mutate()
            .header("X-User-Id", userInfo.getUserId().toString())
            .header("X-Username", userInfo.getUsername())
            .header("X-User-Roles", String.join(",", userInfo.getRoles()))
            .header("X-User-Permissions", String.join(",", userInfo.getPermissions()))
            .build();
        
        // 3. 移除原始 Authorization 头（可选）
        request = request.mutate()
            .headers(headers -> headers.remove("Authorization"))
            .build();
        
        return chain.filter(exchange.mutate().request(request).build());
    }
    
    @Override
    public int getOrder() {
        return -100; // 优先级
    }
}
```

---

## 🔧 配置参考

### 完整配置项

```yaml
winter:
  security:
    # 白名单配置
    whitelist:
      urls:
        - /actuator/**
        - /auth/**
        - /swagger-ui/**
    
    # 请求头配置
    user-id-header: X-User-Id              # 用户ID请求头
    username-header: X-Username            # 用户名请求头
    roles-header: X-User-Roles             # 角色请求头
    permissions-header: X-User-Permissions # 权限请求头
    authorization-header: Authorization    # JWT认证头
    bearer-prefix: "Bearer "               # JWT前缀
    
    # 分隔符配置
    gateway-role-and-permission-separator: ","  # 角色和权限分隔符
```

---

## 🤝 贡献指南

欢迎贡献代码、提出问题和建议！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

---

## 📄 开源协议

本项目采用 [Apache License 2.0](LICENSE) 开源协议。

---

## 👨‍💻 作者

**dadandiaoming**
- Email: 2595915122@qq.com
- GitHub: [@hahaha-zsq](https://github.com/hahaha-zsq)

---

## ⭐ Star History

如果这个项目对你有帮助，请给个 Star ⭐️ 支持一下！

---

## 📮 联系方式

- 提交 Issue: [GitHub Issues](https://github.com/hahaha-zsq/winter-security-spring-boot-starter/issues)
- 邮件联系: 2595915122@qq.com

---

<div align="center">

**[⬆ 回到顶部](#winter-security-spring-boot-starter)**

Made with ❤️ by dadandiaoming

</div>

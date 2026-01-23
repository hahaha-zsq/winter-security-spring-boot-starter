package com.zsq.winter.security.filter;


import com.zsq.winter.security.config.SecurityProperties;
import com.zsq.winter.security.config.TokenAuthenticator;
import com.zsq.winter.security.context.WinterSecurityContextHolder;
import com.zsq.winter.security.model.CustomUserDetails;
import com.zsq.winter.security.model.ValidateToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT认证过滤器 - 支持网关和直连双路径认证
 * 
 * 核心功能：
 * 1. 网关认证：从HTTP头获取网关传递的用户信息
 * 2. JWT直连认证：解析JWT token进行身份验证
 * 3. 上下文管理：设置Spring Security和自定义上下文，请求结束后自动清理
 * 
 * 认证流程：
 * 1. 优先检查网关传递的用户信息（X-User-*头）
 * 2. 如果没有网关信息，则尝试JWT直连认证
 * 3. 认证成功后同时设置自定义上下文和Spring Security上下文
 * 4. 请求处理完成后自动清理上下文，防止线程池复用导致的数据污染
 * 
 * @author dandandiaoming
 */
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /**
     * Token认证器，用于JWT验证和用户信息获取
     */
    private final TokenAuthenticator tokenAuthenticator;
    
    /**
     * 安全配置属性，包含请求头名称、白名单等配置信息
     */
    private final SecurityProperties securityProperties;

    /**
     * 构造函数 - 注入依赖的认证服务
     * 
     * @param tokenAuthenticator Token认证器实现
     * @param securityProperties 安全配置属性
     */
    public JwtAuthenticationFilter(TokenAuthenticator tokenAuthenticator, SecurityProperties securityProperties) {
        this.tokenAuthenticator = tokenAuthenticator;
        this.securityProperties = securityProperties;
    }

    /**
     * 过滤器核心方法 - 实现双路径认证逻辑
     * <p>
     * 【实现原理】
     * 1. 优先检查网关传递的用户信息（X-User-*头）
     * 2. 如果没有网关信息，则尝试JWT直连认证
     * 3. 认证成功后同时设置自定义上下文和Spring Security上下文
     * 4. 异常不阻断请求，保证系统的健壮性
     * <p>
     * 【设计考虑】
     * - 网关认证优先：提高性能，避免重复JWT解析
     * - 异常隔离：认证失败不影响请求继续处理
     * - 双上下文：兼容现有代码和Spring Security标准
     *
     * @param request     HTTP请求对象
     * @param response    HTTP响应对象
     * @param filterChain 过滤器链，用于继续请求处理
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            // 检查网关认证信息（网关需要移除用户手动传递的这些请求头，防止伪造）
            String userId = request.getHeader(securityProperties.getUserIdHeader());
            String username = request.getHeader(securityProperties.getUsernameHeader());

            if (!ObjectUtils.isEmpty(userId) && !ObjectUtils.isEmpty(username)) {
                // 网关路径认证
                handleGatewayAuthentication(request);
                log.debug("通过网关认证: userId={}, username={}", userId, username);
            } else {
                // JWT直连认证
                String authHeader = request.getHeader(securityProperties.getAuthorizationHeader());
                if (StringUtils.hasText(authHeader) && authHeader.startsWith(securityProperties.getBearerPrefix())) {
                    String token = authHeader.substring(securityProperties.getBearerPrefix().length());
                    handleDirectAuthentication(token);
                    log.debug("通过JWT直接认证");
                }
            }
        } catch (Exception e) {
            log.error("认证过程中发生异常", e);
            // 清理可能设置的上下文，避免污染
            clearContext();
        } finally {
            try {
                // 继续过滤器链
                filterChain.doFilter(request, response);
            } finally {
                // 请求处理完成后，确保清理上下文，防止线程池复用导致的数据污染
                clearContext();
            }
        }
    }

    /**
     * 清理认证上下文
     */
    private void clearContext() {
        WinterSecurityContextHolder.clear();
        SecurityContextHolder.clearContext();
    }

    /**
     * 处理网关路径的认证
     * 从HTTP头提取网关传递的用户信息并设置到上下文中
     */
    private void handleGatewayAuthentication(HttpServletRequest request) {
        String userId = request.getHeader(securityProperties.getUserIdHeader());
        String username = request.getHeader(securityProperties.getUsernameHeader());
        String rolesStr = request.getHeader(securityProperties.getRolesHeader());
        String permissionsStr = request.getHeader(securityProperties.getPermissionsHeader());

        List<String> roles = parseStringList(rolesStr);
        List<String> permissions = parseStringList(permissionsStr);

        // 设置自定义上下文
        WinterSecurityContextHolder.setContext(userId, username, roles, permissions);

        // 构造Spring Security权限列表
        List<SimpleGrantedAuthority> authorities = permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        // 创建用户详情对象
        CustomUserDetails userDetails = new CustomUserDetails();
        userDetails.setUserId(Long.valueOf(userId));
        userDetails.setUsername(username);
        userDetails.setRoles(roles);
        userDetails.setPermissions(permissions);

        // 设置Spring Security认证上下文
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, authorities);

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    /**
     * 处理JWT直连认证（开发人员直接访问其他微服务，不经过网关，这样就需要直接判断token是否正确，并设置正确的权限信息）
     * 调用TokenAuthenticator验证token并设置上下文
     */
    private void handleDirectAuthentication(String token) {
        try {
            TokenAuthenticator.AuthResult authenticate = tokenAuthenticator.authenticate(token);
            ValidateToken validateResult = authenticate.getData();

            if (validateResult != null && validateResult.getValid() && validateResult.getUserId() != null) {
                // 设置自定义上下文
                WinterSecurityContextHolder.setContext(
                        validateResult.getUserId().toString(),
                        validateResult.getUserName(),
                        !ObjectUtils.isEmpty(validateResult.getRoles()) ? validateResult.getRoles() : Collections.emptyList(),
                        !ObjectUtils.isEmpty(validateResult.getPermissions()) ? validateResult.getPermissions() : Collections.emptyList()
                );

                // 构造Spring Security权限
                List<SimpleGrantedAuthority> authorities =
                        !ObjectUtils.isEmpty(validateResult.getPermissions()) ?
                                validateResult.getPermissions().stream()
                                        .map(SimpleGrantedAuthority::new)
                                        .collect(Collectors.toList()) : Collections.emptyList();

                // 创建用户详情对象
                CustomUserDetails userDetails = new CustomUserDetails();
                userDetails.setUserId(validateResult.getUserId());
                userDetails.setUsername(validateResult.getUserName());
                userDetails.setRoles(validateResult.getRoles());
                userDetails.setPermissions(validateResult.getPermissions());

                // 设置Spring Security上下文
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, authorities);

                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.debug("直接认证成功: userId={}, username={}",
                        validateResult.getUserId(), validateResult.getUserName());
            } else {
                log.warn("Token 验证失败: {}",
                        validateResult != null ? authenticate.getErrorMessage() : "验证结果为空");
            }
        } catch (Exception e) {
            log.error("直接认证失败", e);
            throw e; // 重新抛出异常，让外层统一处理
        }
    }

    /**
     * 解析逗号分隔的字符串为列表
     */
    private List<String> parseStringList(String str) {
        if (ObjectUtils.isEmpty(str)) {
            return Collections.emptyList();
        }
        // 这是 Arrays.asList(...) 返回的内部类，不是标准的 java.util.ArrayList。
        // 出于安全考虑（防止反序列化任意类造成 RCE 等漏洞），Spring Security 从某个版本开始默认启用了 Jackson 的“类型白名单”机制（Type Allowlist）。只有明确允许的类才能被反序列化。
        return Arrays.stream(str.split(securityProperties.getGatewayRoleAndPermissionSeparator())).collect(Collectors.toList());
    }
}
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
 * JWT认证过滤器 - 微服务双路径认证的核心组件
 * <p>
 * 【核心功能实现原理】
 * 1. 继承OncePerRequestFilter确保每个请求只执行一次认证
 * 2. 实现双路径认证机制，支持网关和直连两种场景
 * 3. 集成Spring Security上下文，确保认证信息的标准化传递
 * 4. 使用TransmittableThreadLocal保证跨线程上下文传递
 * <p>
 * 【代码结构设计思路】
 * - 采用策略模式：根据请求特征选择不同的认证策略
 * - 职责分离：网关认证和直连认证分别处理，降低耦合度
 * - 异常隔离：认证失败不阻断请求，交由Spring Security后续处理
 * - 上下文双写：同时设置自定义上下文和Spring Security上下文
 * <p>
 * 【解决的具体业务问题】
 * 1. 微服务架构下的统一认证问题：支持网关集中认证和服务直连认证
 * 2. 认证信息传递问题：解决微服务间用户身份和权限信息的可靠传递
 * 3. 向后兼容问题：保持对现有LoginContextHolder的兼容性
 * 4. 性能优化问题：避免重复的JWT解析和用户信息查询
 * <p>
 * 【与其他模块的交互关系】
 * - AuthFeignService：调用认证服务进行JWT验证和用户信息获取
 * - LoginContextHolder：设置自定义用户上下文，支持业务代码直接使用
 * - SecurityContextHolder：设置Spring Security标准上下文，支持@PreAuthorize等注解
 * - CustomUserDetails：封装用户详情，实现Spring Security UserDetails接口
 * - SecurityConfig：作为过滤器链的一环，在权限检查之前执行
 *
 * @author zsq
 */
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /**
     * 认证服务，用于JWT验证和用户信息获取
     */
    private final TokenAuthenticator tokenAuthenticator;
    private final SecurityProperties securityProperties;

    /**
     * 构造函数注入认证服务客户端
     * Spring会自动注入AuthFeignClient实例
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
            // ==================== 第一步：检查网关认证信息 ====================
            // 网关在认证成功后会将用户信息通过HTTP头传递给下游服务
            // 这种方式性能更好，避免了重复的JWT解析和数据库查询
            String userId = request.getHeader(securityProperties.getUserIdHeader());
            String username = request.getHeader(securityProperties.getUsernameHeader());

            if (!ObjectUtils.isEmpty(userId) && !ObjectUtils.isEmpty(username)) {
                // 路径1: 网关路径 - 从请求头构造Authentication
                // 这是推荐的认证方式，性能最优
                handleGatewayAuthentication(request);
                log.debug("通过网关认证: userId={}, username={}", userId, username);
            } else {
                // ==================== 第二步：尝试JWT直连认证 ====================
                // 当服务绕过网关直接访问时，需要通过JWT进行认证
                // 这种情况通常发生在内部服务调用或开发测试环境
                String authHeader = request.getHeader(securityProperties.getAuthorizationHeader());
                if (StringUtils.hasText(authHeader) && authHeader.startsWith(securityProperties.getBearerPrefix())) {
                    String token = authHeader.substring(securityProperties.getBearerPrefix().length());
                    handleDirectAuthentication(token);
                    log.debug("通过JWT直接认证");
                }
            }
        } catch (Exception e) {
            // ==================== 异常处理策略 ====================
            // 认证异常不应该阻断请求处理，而是交由Spring Security的其他机制处理
            // 这样可以保证系统的健壮性，避免因认证服务异常导致整个系统不可用
            log.error("认证过程中发生异常", e);
            // 不阻断请求，让Spring Security的其他机制处理
        }

        // ==================== 继续过滤器链 ====================
        // 无论认证是否成功，都要继续执行后续的过滤器
        // Spring Security会在后续的过滤器中进行权限检查
        filterChain.doFilter(request, response);
    }

    /**
     * 处理网关路径的认证 - 高性能认证方案
     * <p>
     * 【实现原理】
     * 网关在JWT验证成功后，将用户信息通过HTTP头传递给下游服务
     * 避免了下游服务重复进行JWT解析和用户信息查询，大幅提升性能
     * <p>
     * 【处理流程】
     * 1. 从HTTP头提取用户基本信息（ID、用户名）
     * 2. 从HTTP头提取用户权限信息（角色、权限列表）
     * 3. 设置LoginContextHolder上下文（向后兼容）
     * 4. 构造Spring Security的Authentication对象
     * 5. 设置SecurityContextHolder（标准Spring Security流程）
     * <p>
     * 【设计优势】
     * - 性能优化：避免重复的JWT解析和数据库查询
     * - 集中管理：网关统一处理认证逻辑，下游服务专注业务
     * - 安全性：内网传输，减少JWT在网络中的传播
     *
     * @param request HTTP请求对象，包含网关传递的用户信息
     */
    private void handleGatewayAuthentication(HttpServletRequest request) {
        // ==================== 第一步：提取基本用户信息 ====================
        String userId = request.getHeader(securityProperties.getUserIdHeader());
        String username = request.getHeader(securityProperties.getUsernameHeader());
        String rolesStr = request.getHeader(securityProperties.getRolesHeader());
        String permissionsStr = request.getHeader(securityProperties.getPermissionsHeader());

        // ==================== 第二步：解析权限信息 ====================
        // 网关传递的角色和权限是逗号分隔的字符串，需要解析为列表
        List<String> roles = parseStringList(rolesStr);
        List<String> permissions = parseStringList(permissionsStr);

        // ==================== 第三步：设置自定义上下文（向后兼容） ====================
        // 保持对现有业务代码的兼容性，业务代码可以通过LoginContextHolder获取用户信息
        WinterSecurityContextHolder.setContext(userId, username, roles, permissions);

        // ==================== 第四步：构造Spring Security权限列表 ====================
        // 将权限字符串转换为Spring Security的GrantedAuthority对象
        // 这样@PreAuthorize等注解就可以正常工作
        List<SimpleGrantedAuthority> authorities = permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        // ==================== 第五步：创建自定义用户详情对象 ====================
        // CustomUserDetails实现了Spring Security的UserDetails接口
        // 封装了用户的完整信息，包括ID、用户名、角色、权限等
        CustomUserDetails userDetails = new CustomUserDetails();
        userDetails.setUserId(Long.valueOf(userId));
        userDetails.setUsername(username);
        userDetails.setRoles(roles);
        userDetails.setPermissions(permissions);

        // ==================== 第六步：设置Spring Security认证上下文 ====================
        // 创建认证令牌并设置到SecurityContextHolder中
        // 这样Spring Security的安全机制就可以正常工作
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, authorities);

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    /**
     * 处理绕过网关的直接认证 - 兼容性认证方案
     * <p>
     * 【应用场景】
     * 1. 开发测试环境：开发人员直接访问服务，绕过网关
     * 2. 内部服务调用：某些内部服务需要直接调用其他服务
     * 3. 网关故障：网关不可用时的降级方案
     * 4. 特殊接口：某些接口需要绕过网关的特殊处理
     * <p>
     * 【实现原理】
     * 通过JWT token调用认证服务验证用户身份，获取完整的用户信息
     * 相比网关认证，这种方式会产生额外的网络调用和数据库查询
     * <p>
     * 【处理流程】
     * 1. 构造用户验证请求对象
     * 2. 调用认证服务的validateUser接口
     * 3. 解析返回的用户信息
     * 4. 设置双重上下文（自定义+Spring Security）
     * <p>
     * 【异常处理】
     * 认证失败不抛出异常，而是记录日志并继续处理
     * 让Spring Security的后续机制来处理未认证的请求
     *
     * @param token JWT令牌字符串
     */
    private void handleDirectAuthentication(String token) {
        try {
            // ==================== 第一步：调用认证服务验证 Token ====================
            // 通过Feign客户端调用认证中心的Token验证接口
            // 这里会进行JWT解析、签名验证、过期检查等操作

            TokenAuthenticator.AuthResult authenticate = tokenAuthenticator.authenticate(token);
            ValidateToken validateResult = authenticate.getData();


            // ==================== 第二步：验证返回结果 ====================
            if (validateResult != null && validateResult.getValid() && validateResult.getUserId() != null) {
                // ==================== 第三步：设置自定义上下文 ====================
                // 保持向后兼容性，现有业务代码可以继续使用LoginContextHolder
                WinterSecurityContextHolder.setContext(
                        validateResult.getUserId().toString(),
                        validateResult.getUserName(),
                        !ObjectUtils.isEmpty(validateResult.getRoles()) ? validateResult.getRoles() : Collections.emptyList(),
                        !ObjectUtils.isEmpty(validateResult.getPermissions()) ? validateResult.getPermissions() : Collections.emptyList()
                );

                // ==================== 第四步：构造Spring Security权限 ====================
                // 将用户权限转换为Spring Security的GrantedAuthority
                List<SimpleGrantedAuthority> authorities =
                        !ObjectUtils.isEmpty(validateResult.getPermissions()) ?
                                validateResult.getPermissions().stream()
                                        .map(SimpleGrantedAuthority::new)
                                        .collect(Collectors.toList()) : Collections.emptyList();

                // ==================== 第五步：创建用户详情对象 ====================
                CustomUserDetails userDetails = new CustomUserDetails();
                userDetails.setUserId(validateResult.getUserId());
                userDetails.setUsername(validateResult.getUserName());
                userDetails.setRoles(validateResult.getRoles());
                userDetails.setPermissions(validateResult.getPermissions());

                // ==================== 第六步：设置Spring Security上下文 ====================
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
            // ==================== 异常处理策略 ====================
            // 直接认证失败时，不抛出异常，而是记录日志
            // 这样可以保证系统的健壮性，让Spring Security的其他机制来处理
            log.error("直接认证失败", e);
        }
    }

    /**
     * 解析字符串列表 - 工具方法
     * <p>
     * 【功能说明】
     * 将逗号分隔的字符串解析为字符串列表
     * 主要用于解析网关传递的角色和权限信息
     * <p>
     * 【处理逻辑】
     * 1. 检查输入字符串是否为空或null
     * 2. 如果为空，返回空列表而不是null，避免NPE
     * 3. 按逗号分割字符串，转换为列表
     * <p>
     * 【设计考虑】
     * - 空值安全：避免返回null，统一返回空列表
     * - 简单高效：使用Arrays.asList进行快速转换
     * - 职责单一：专门处理字符串解析，提高代码复用性
     *
     * @param str 待解析的字符串，格式如"role1,role2,role3"
     * @return 解析后的字符串列表，如果输入为空则返回空列表
     */
    private List<String> parseStringList(String str) {
        // 检查字符串是否有效
        if (ObjectUtils.isEmpty(str)) {
            // 返回空列表而不是null，避免后续处理中的空指针异常
            return Collections.emptyList();
        }
        // 按逗号分割字符串并转换为列表
        return Arrays.asList(str.split(securityProperties.getGatewayRoleAndPermissionSeparator()));
    }
}
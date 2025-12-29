package com.zsq.winter.security.model;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 自定义用户详情类 - Spring Security用户认证和授权的核心载体
 * 
 * 【核心功能实现原理】
 * 1. 实现Spring Security的UserDetails接口，提供用户认证所需的核心信息
 * 2. 扩展标准UserDetails，增加用户ID、角色、权限等业务相关信息
 * 3. 提供权限转换机制，将业务权限转换为Spring Security的GrantedAuthority
 * 4. 支持账户状态管理，包括过期、锁定、启用等状态控制
 * 
 * 【代码结构设计思路】
 * - 接口实现：严格实现UserDetails接口，确保与Spring Security的兼容性
 * - 业务扩展：在标准接口基础上增加业务相关的用户信息
 * - 权限映射：提供权限字符串到GrantedAuthority的转换机制
 * - 状态管理：提供完整的账户状态控制能力
 * - 便捷方法：提供角色和权限检查的便捷方法
 * 
 * 【解决的具体业务问题】
 * 1. 认证信息标准化：提供Spring Security标准的用户认证信息
 * 2. 权限模型适配：将业务系统的权限模型适配到Spring Security
 * 3. 用户状态管理：支持用户账户的各种状态控制（启用、锁定、过期等）
 * 4. 业务信息扩展：在认证信息中携带业务相关的用户信息
 * 5. 权限检查简化：提供便捷的权限和角色检查方法
 * 
 * 【与其他模块的交互关系】
 * - Spring Security：作为认证主体存储在SecurityContext中
 * - JwtAuthenticationFilter：在JWT认证成功后创建此对象
 * - CustomAuthenticationDetails：配合使用，提供完整的认证信息
 * - 权限控制：为方法级和URL级权限控制提供权限信息
 * - 业务代码：通过SecurityContextHolder获取当前用户信息
 * 
 * 【权限模型说明】
 * - 角色(Role)：粗粒度权限控制，用于功能模块级别的访问控制
 * - 权限(Permission)：细粒度权限控制，用于具体操作的访问控制
 * - GrantedAuthority：Spring Security的权限接口，由权限列表转换而来
 * 
 * @author zsq
 */
@Data
public class CustomUserDetails implements UserDetails {

    /**
     * 用户唯一标识 - 业务系统中的用户主键
     * 
     * 【扩展字段说明】
     * 这是对标准UserDetails的扩展，用于在认证过程中携带业务相关的用户标识
     * 
     * 【用途说明】
     * - 业务关联：与业务数据进行关联查询
     * - 权限控制：基于用户ID进行数据权限控制
     * - 审计日志：记录操作用户的唯一标识
     * - 缓存管理：作为用户相关缓存的键值
     */
    private Long userId;

    /**
     * 用户登录名 - UserDetails接口要求的核心字段
     * 
     * 【Spring Security要求】
     * 这是UserDetails接口的核心字段，用于用户身份识别
     * 
     * 【业务用途】
     * - 身份识别：作为用户的唯一登录标识
     * - 显示用途：在前端界面显示当前登录用户
     * - 日志记录：在操作日志中记录用户名
     * - 审计追踪：在审计报告中显示操作者
     */
    private String username;

    /**
     * 用户密码 - 通常为空（JWT认证模式下不需要密码）
     * 
     * 【设计说明】
     * 在JWT认证模式下，用户密码验证在认证服务中完成
     * 此字段通常为空，避免在内存中存储敏感信息
     * 
     * 【安全考虑】
     * - 不存储明文密码，提高安全性
     * - JWT模式下无需密码，减少内存占用
     * - 如需密码验证，应在认证服务中处理
     */
    private String password;

    /**
     * 用户角色列表 - 粗粒度权限控制
     * 
     * 【权限模型】
     * 角色是权限的集合，用于功能模块级别的访问控制
     * 
     * 【数据格式】
     * 通常存储角色编码，如：["ADMIN", "USER", "MANAGER"]
     * 
     * 【应用场景】
     * - 菜单控制：根据角色显示不同的菜单项
     * - 功能访问：控制用户可以访问的功能模块
     * - 业务流程：不同角色执行不同的业务逻辑
     */
    private List<String> roles;

    /**
     * 用户权限列表 - 细粒度权限控制
     * 
     * 【权限模型】
     * 权限是最小的访问控制单元，用于精确控制用户操作
     * 
     * 【数据格式】
     * 通常采用资源:操作的格式，如：["user:read", "user:write", "order:delete"]
     * 
     * 【Spring Security集成】
     * 通过getAuthorities()方法转换为GrantedAuthority对象
     * 
     * 【应用场景】
     * - API访问控制：控制用户可以调用哪些接口
     * - 数据操作权限：控制用户对数据的增删改查权限
     * - 按钮级控制：控制页面上按钮的显示和可用性
     */
    private List<String> permissions;

    /**
     * 账户是否未过期 - Spring Security账户状态控制
     * 
     * 【状态说明】
     * true：账户未过期，可以正常使用
     * false：账户已过期，无法进行认证
     * 
     * 【业务场景】
     * - 会员到期：会员账户到期后设置为过期
     * - 临时账户：临时账户超过有效期后自动过期
     * - 安全管控：对特定账户设置过期时间
     */
    private boolean accountNonExpired = true;

    /**
     * 账户是否未锁定 - Spring Security账户状态控制
     * 
     * 【状态说明】
     * true：账户未锁定，可以正常使用
     * false：账户已锁定，无法进行认证
     * 
     * 【业务场景】
     * - 安全防护：多次登录失败后自动锁定账户
     * - 管理员操作：管理员手动锁定违规账户
     * - 风险控制：检测到异常行为后锁定账户
     */
    private boolean accountNonLocked = true;

    /**
     * 凭证是否未过期 - Spring Security凭证状态控制
     * 
     * 【状态说明】
     * true：凭证未过期，可以正常使用
     * false：凭证已过期，需要重新认证
     * 
     * 【业务场景】
     * - 密码过期：强制用户定期更换密码
     * - Token过期：JWT或其他Token过期后需要刷新
     * - 安全策略：定期要求用户重新认证
     */
    private boolean credentialsNonExpired = true;

    /**
     * 账户是否启用 - Spring Security账户状态控制
     * 
     * 【状态说明】
     * true：账户已启用，可以正常使用
     * false：账户已禁用，无法进行认证
     * 
     * 【业务场景】
     * - 新用户激活：新注册用户需要激活后才能使用
     * - 管理员控制：管理员可以禁用特定用户账户
     * - 业务流程：根据业务规则启用或禁用账户
     */
    private boolean enabled = true;

    /**
     * 获取用户权限集合 - Spring Security权限转换的核心方法
     * 
     * 【接口要求】
     * 这是UserDetails接口的核心方法，Spring Security通过此方法获取用户权限
     * 
     * 【转换逻辑】
     * 将业务系统的权限字符串转换为Spring Security的GrantedAuthority对象
     * 
     * 【实现原理】
     * 1. 检查权限列表是否为空，为空则返回空集合
     * 2. 使用Stream API将权限字符串转换为SimpleGrantedAuthority对象
     * 3. 返回GrantedAuthority集合，供Spring Security使用
     * 
     * 【权限格式】
     * 输入：["user:read", "user:write", "order:delete"]
     * 输出：[SimpleGrantedAuthority("user:read"), SimpleGrantedAuthority("user:write"), ...]
     * 
     * 【性能考虑】
     * - 使用Stream API提高代码可读性
     * - 空值检查避免NullPointerException
     * - 返回不可变集合，提高安全性
     * 
     * @return Collection<? extends GrantedAuthority> Spring Security权限集合
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 空值检查：如果权限列表为空，返回空集合
        if (permissions == null || permissions.isEmpty()) {
            return Collections.emptyList();
        }
        
        // 权限转换：将权限字符串转换为GrantedAuthority对象
        return permissions.stream()
                .map(SimpleGrantedAuthority::new)  // 创建SimpleGrantedAuthority对象
                .collect(Collectors.toList());     // 收集为List集合
    }

    /**
     * 获取用户密码 - UserDetails接口方法
     * 
     * 【JWT认证说明】
     * 在JWT认证模式下，此方法通常返回null或空字符串
     * 因为密码验证在认证服务中完成，不需要在此处存储密码
     * 
     * 【安全考虑】
     * 避免在内存中长时间存储用户密码，提高系统安全性
     * 
     * @return String 用户密码（JWT模式下通常为空）
     */
    @Override
    public String getPassword() {
        return this.password;
    }

    /**
     * 获取用户名 - UserDetails接口方法
     * 
     * 【身份标识】
     * 返回用户的唯一登录标识，用于Spring Security的身份识别
     * 
     * @return String 用户登录名
     */
    @Override
    public String getUsername() {
        return this.username;
    }

    /**
     * 账户是否未过期 - UserDetails接口方法
     * 
     * 【状态检查】
     * Spring Security在认证过程中会检查此状态
     * 如果返回false，认证将失败
     * 
     * @return boolean 账户是否未过期
     */
    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    /**
     * 账户是否未锁定 - UserDetails接口方法
     * 
     * 【状态检查】
     * Spring Security在认证过程中会检查此状态
     * 如果返回false，认证将失败
     * 
     * @return boolean 账户是否未锁定
     */
    @Override
    public boolean isAccountNonLocked() {
        return this.accountNonLocked;
    }

    /**
     * 凭证是否未过期 - UserDetails接口方法
     * 
     * 【状态检查】
     * Spring Security在认证过程中会检查此状态
     * 如果返回false，认证将失败
     * 
     * @return boolean 凭证是否未过期
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNonExpired;
    }

    /**
     * 账户是否启用 - UserDetails接口方法
     * 
     * 【状态检查】
     * Spring Security在认证过程中会检查此状态
     * 如果返回false，认证将失败
     * 
     * @return boolean 账户是否启用
     */
    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    /**
     * 检查用户是否具有指定角色 - 便捷的角色检查方法
     * 
     * 【业务用途】
     * 在业务代码中快速检查用户是否具有特定角色
     * 
     * 【使用示例】
     * if (userDetails.hasRole("ADMIN")) {
     *     // 执行管理员操作
     * }
     * 
     * 【实现逻辑】
     * 检查角色列表中是否包含指定角色
     * 
     * @param role 角色名称
     * @return boolean 是否具有指定角色
     */
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    /**
     * 检查用户是否具有指定权限 - 便捷的权限检查方法
     * 
     * 【业务用途】
     * 在业务代码中快速检查用户是否具有特定权限
     * 
     * 【使用示例】
     * if (userDetails.hasPermission("user:write")) {
     *     // 执行用户写操作
     * }
     * 
     * 【实现逻辑】
     * 检查权限列表中是否包含指定权限
     * 
     * @param permission 权限名称
     * @return boolean 是否具有指定权限
     */
    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }
}
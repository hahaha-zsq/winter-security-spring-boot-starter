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
 * 实现UserDetails接口，提供用户认证所需的核心信息
 * 扩展标准UserDetails，增加用户ID、角色、权限等业务相关信息
 * 
 * @author zsq
 */
@Data
public class CustomUserDetails implements UserDetails {

    private Long userId;
    private String username;
    private String password;
    private List<String> roles;
    private List<String> permissions;
    
    // 账户状态
    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;
    
    // 缓存权限列表，避免重复创建
    private transient Collection<? extends GrantedAuthority> authorities;

    /**
     * 获取用户权限集合
     * 将业务权限字符串转换为Spring Security的GrantedAuthority对象
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 使用缓存，避免重复创建
        if (authorities == null) {
            if (permissions == null || permissions.isEmpty()) {
                authorities = Collections.emptyList();
            } else {
                authorities = permissions.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
            }
        }
        return authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    /**
     * 检查用户是否具有指定角色
     */
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    /**
     * 检查用户是否具有指定权限
     */
    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }
    
    /**
     * 设置权限列表时清除缓存
     */
    public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
        this.authorities = null; // 清除缓存
    }
}
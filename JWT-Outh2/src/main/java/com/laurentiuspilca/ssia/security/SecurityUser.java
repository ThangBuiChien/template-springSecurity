package com.laurentiuspilca.ssia.security;

import com.laurentiuspilca.ssia.entity.Users;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;


public class SecurityUser implements UserDetails, OAuth2User {

    private final Users user;
    private Map<String, Object> attributes;

    // Constructor for regular authentication
    public SecurityUser(Users user) {
        this.user = user;
        this.attributes = new HashMap<>();
    }

    // Factory method to create from Users and OAuth2 attributes
    public static SecurityUser create(Users user, Map<String, Object> attributes) {
        return new SecurityUser(user, attributes);
    }

    // Constructor for OAuth2 authentication
    public SecurityUser(Users user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    public Long getId(){
        return user.getId();
    }



    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUserName();
    }

    // OAuth2User methods


    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return String.valueOf(user.getId());
    }
}

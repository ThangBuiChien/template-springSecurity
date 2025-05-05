package com.laurentiuspilca.ssia.services;

import com.laurentiuspilca.ssia.entity.Users;
import com.laurentiuspilca.ssia.security.auth.JwtAuthResponse;
import com.laurentiuspilca.ssia.security.auth.LoginRequest;
import com.laurentiuspilca.ssia.security.jwt.JwtTokenProvider;
import com.laurentiuspilca.ssia.security.jwt.JwtTokenProviderSecure;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProviderSecure tokenProvider;
    private final UserService userService;
    private static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";

    public Authentication authenticate(String username, String password) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return authentication;
    }

    public String generateAccessToken(Authentication authentication) {
        return tokenProvider.generateAccessToken(authentication);
    }

    public String generateAccessToken(String username) {
        return tokenProvider.generateAccessTokenFromUsername(username);
    }

    public UUID createRefreshToken(String username) {
        return userService.createRefreshToken(username);
    }

    public Optional<Users> findByRefreshToken(UUID refreshTokenUuid) {
        return userService.findByRefreshToken(refreshTokenUuid);
    }

    public void invalidateRefreshToken(String username) {
        userService.invalidateRefreshToken(username);
    }

    public Cookie createRefreshTokenCookie(String refreshToken) {
        Cookie cookie = new Cookie(REFRESH_TOKEN_COOKIE_NAME, refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/api/auth");
        cookie.setMaxAge(7 * 24 * 60 * 60); // 7 days in seconds
        return cookie;
    }

    public Cookie createExpiredRefreshTokenCookie() {
        Cookie cookie = new Cookie(REFRESH_TOKEN_COOKIE_NAME, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0); // Delete the cookie
        return cookie;
    }

    public Optional<Cookie> extractRefreshTokenCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }

        return Arrays.stream(cookies)
                .filter(cookie -> REFRESH_TOKEN_COOKIE_NAME.equals(cookie.getName()))
                .findFirst();
    }
}


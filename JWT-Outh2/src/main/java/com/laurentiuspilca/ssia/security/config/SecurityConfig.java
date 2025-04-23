package com.laurentiuspilca.ssia.security.config;

import com.laurentiuspilca.ssia.security.jwt.JwtAuthenticationEntryPoint;
import com.laurentiuspilca.ssia.security.jwt.JwtAuthenticationFilter;
import com.laurentiuspilca.ssia.security.outh2.OAuth2AuthenticationSuccessHandler;
import com.laurentiuspilca.ssia.security.service.CustomOAuth2UserService;
import com.laurentiuspilca.ssia.security.service.CustomUserDetailService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationEntryPoint unauthorizedHandler;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomUserDetailService userDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }


    @Bean
    SecurityFilterChain configure(HttpSecurity http) throws Exception {

//        http
//                .csrf(csrf -> csrf.disable())
//                .exceptionHandling(exceptions -> exceptions
//                        .authenticationEntryPoint(unauthorizedHandler))
//                .sessionManagement(session -> session
//                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/api/auth/**", "/public/**", "/roles", "/api/users",
//                                "/login", "/oauth2/**").permitAll()
////                        .anyRequest().hasRole("USER"));
//                        .anyRequest().permitAll())
//                .formLogin(Customizer.withDefaults())
//                .oauth2Login(oauth2 -> oauth2
//                        .authorizationEndpoint(endpoint -> endpoint
//                                .baseUri("/oauth2/authorize"))
//                        .redirectionEndpoint(endpoint -> endpoint
//                                .baseUri("/oauth2/callback/*"))
//                        .userInfoEndpoint(userInfo -> userInfo
//                                .userService(customOAuth2UserService))
//                        .successHandler(oAuth2AuthenticationSuccessHandler));;

        http.formLogin(Customizer.withDefaults());  // Use form login instead of basic auth


        http.authorizeHttpRequests(c -> c
                .requestMatchers("/users", "/roles").permitAll()
                        .requestMatchers("/hello").hasRole("USER")
                .anyRequest().permitAll()
        )
                        .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(endpoint -> endpoint
                                .baseUri("/oauth2/authorize"))
                        .redirectionEndpoint(endpoint -> endpoint
                                .baseUri("/oauth2/callback/*"))
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService))
                        .successHandler(oAuth2AuthenticationSuccessHandler));;

        http.csrf(AbstractHttpConfigurer::disable);


        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }


}

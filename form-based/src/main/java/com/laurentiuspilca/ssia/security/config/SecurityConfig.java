package com.laurentiuspilca.ssia.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Bean
    SecurityFilterChain configure(HttpSecurity http) throws Exception {

//        http.httpBasic(Customizer.withDefaults());

        http.formLogin(Customizer.withDefaults());  // Use form login instead of basic auth


//        http.addFilterBefore(new RequestValidationFilter(), BasicAuthenticationFilter.class)
//                .addFilterAfter(new AuthenticationLoggingFilter(), BasicAuthenticationFilter.class);

        http.authorizeHttpRequests(c -> c
                .requestMatchers("/users", "/roles").permitAll()
                .anyRequest().permitAll()
        );

        http.csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }


}

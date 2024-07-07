package com.amdaris.ssf;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Value("${SERVICE_KEY}")
    private String serviceKey;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(serviceKey);

        return http
                .httpBasic(Customizer.withDefaults())
                .addFilterAfter(customAuthenticationFilter, BasicAuthenticationFilter.class)
                .authorizeHttpRequests(
                        c -> c.anyRequest().authenticated()
                )
                .logout(
                        logout -> logout
                                .invalidateHttpSession(true)
                                .clearAuthentication(true)
                                .deleteCookies("JSESSIONID")
                        .logoutUrl("/logout")
                )
                .build();
    }

}

package com.amdaris.ssf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@RequiredArgsConstructor
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    public static final String SERVICE_KEY_QUERY_PARAM = "SERVICE_KEY";

    private final String serviceKey;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String providedServiceKey = request.getParameter(SERVICE_KEY_QUERY_PARAM);
        CustomAuthentication customAuth = new CustomAuthentication(false, providedServiceKey);

        CustomAuthenticationManager customAuthenticationManager = new CustomAuthenticationManager(serviceKey);
        try {
            Authentication auth = customAuthenticationManager.authenticate(customAuth);

            if (auth.isAuthenticated()) {
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(auth);
                SecurityContextHolder.setContext(context);
                filterChain.doFilter(request, response);
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        } catch (AuthenticationException ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}

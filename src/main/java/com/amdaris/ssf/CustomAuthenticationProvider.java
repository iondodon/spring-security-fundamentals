package com.amdaris.ssf;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final String serviceKey;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuthentication auth = (CustomAuthentication) authentication;

        if (serviceKey.equals(auth.getServiceKey())) {
            auth.setAuthenticated(true);
            return auth;
        }

        throw new BadCredentialsException("Incorrect SERVICE_KEY");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomAuthentication.class.equals(authentication);
    }
}

package com.amdaris.ssf;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@RequiredArgsConstructor
public class CustomAuthenticationManager implements AuthenticationManager {
    private final String serviceKey;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuthenticationProvider customAuthenticationProvider = new CustomAuthenticationProvider(serviceKey);
        if (customAuthenticationProvider.supports(authentication.getClass())) {
            return customAuthenticationProvider.authenticate(authentication);
        }

        throw new ProviderNotFoundException("Authentication not supported");
    }
}

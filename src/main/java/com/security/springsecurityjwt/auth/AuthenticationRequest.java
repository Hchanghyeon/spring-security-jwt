package com.security.springsecurityjwt.auth;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class AuthenticationRequest {

    private String email;
    private String password;

    @Builder
    public AuthenticationRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }
}

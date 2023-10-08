package com.security.springsecurityjwt.auth;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class AuthenticationResponse {

    private String token;

    @Builder
    public AuthenticationResponse(String token) {
        this.token = token;
    }
}

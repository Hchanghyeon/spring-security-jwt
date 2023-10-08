package com.security.springsecurityjwt.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.security.springsecurityjwt.config.JwtService;
import com.security.springsecurityjwt.repository.UserRepository;
import com.security.springsecurityjwt.user.Role;
import com.security.springsecurityjwt.user.User;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest registerRequest) {
        User user = User.builder()
            .firstname(registerRequest.getFirstname())
            .lastname(registerRequest.getLastname())
            .email(registerRequest.getEmail())
            .password(passwordEncoder.encode(registerRequest.getPassword()))
            .role(Role.USER)
            .build();

        userRepository.save(user);

        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
            .token(jwtToken)
            .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                authenticationRequest.getEmail(),
                authenticationRequest.getPassword()
            )
        );

        User user = userRepository.findByEmail(authenticationRequest.getEmail())
            .orElseThrow();

        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
            .token(jwtToken)
            .build();
    }
}

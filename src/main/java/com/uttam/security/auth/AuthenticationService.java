package com.uttam.security.auth;

import com.uttam.security.ExceptionHandling.ApplicationException;
import com.uttam.security.config.JwtService;
import com.uttam.security.user.RoleRepository;
import com.uttam.security.user.User;
import com.uttam.security.user.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public User register(UserDto request) {

        if (!validateRequest(request)) {
            throw new ApplicationException("Error", "Email, Password, and ConfirmPassword are required but found empty!", HttpStatus.BAD_REQUEST);
        }

        if (!request.getConfirmPassword().equals(request.getPassword())) {
            throw new ApplicationException("Error", "Password and ConfirmPassword should be the same!", HttpStatus.BAD_REQUEST);
        }

        Optional<User> existingUser = repository.findByEmail(request.getEmail());
        if (existingUser.isPresent()) {
            throw new ApplicationException("Conflict", "User already exists with email entered!", HttpStatus.BAD_REQUEST);
        }


        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .active(true)
                .updateOn(LocalDateTime.now())
                .role(roleRepository.findByName("Application_User").orElseThrow(() -> new ApplicationException("Internal Error", "Can't find default role!", HttpStatus.INTERNAL_SERVER_ERROR)))
                .build();
        var savedUser = repository.save(user);
        return user;
    }


    public AuthenticationResponse login(AuthenticationRequest request,  HttpServletResponse response) {
        // 1) Check if email and password exist
        if (!validateLoginRequest(request)) {
            throw new ApplicationException("Error", "Email and Password are required but found empty!", HttpStatus.BAD_REQUEST);
        }

        // Validate email and password
        User existingUser = repository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ApplicationException("Unauthorized", "Incorrect email or password", HttpStatus.UNAUTHORIZED));

        if (!passwordEncoder.matches(request.getPassword(), existingUser.getPassword())) {
            throw new ApplicationException("Unauthorized", "Incorrect email or password", HttpStatus.UNAUTHORIZED);
        }

        // If everything is okay, generate and return tokens
        String jwtToken = jwtService.generateToken(existingUser);
        Cookie cookie = new Cookie("springJwt", jwtToken);
        cookie.setHttpOnly(true);
        cookie.setPath("/"); // Set the cookie path as needed

        response.addCookie(cookie);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build();
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build();
    }


    public boolean validateRequest(UserDto request) {
        return request.getEmail() != null && !request.getEmail().isBlank() &&
                request.getPassword() != null && !request.getPassword().trim().isBlank() &&
                request.getConfirmPassword() != null && !request.getConfirmPassword().trim().isBlank() &&
                request.getFirstname() != null && !request.getFirstname().trim().isBlank() &&
                request.getLastname() != null && !request.getLastname().trim().isBlank();
    }

    public boolean validateLoginRequest(AuthenticationRequest request) {
        return request.getEmail() != null && !request.getEmail().isBlank() &&
                request.getPassword() != null && !request.getPassword().trim().isBlank();
    }
}

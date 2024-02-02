package com.uttam.security.auth;

import com.uttam.security.ApiResponse;
import com.uttam.security.ExceptionHandling.ApplicationException;
import com.uttam.security.user.User;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<User> register(
            @RequestBody UserDto request
    ) {
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthenticationResponse>> login(
            @RequestBody AuthenticationRequest request, HttpServletResponse response
    ) {

        var data = service.login(request, response);
        ApiResponse<AuthenticationResponse> res = ApiResponse.<AuthenticationResponse>builder()
                .status("success")
                .message("Logged in!")
                .data(data)
                .build();

        return ResponseEntity.ok(res);
    }
}

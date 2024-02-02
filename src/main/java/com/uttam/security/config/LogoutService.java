package com.uttam.security.config;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    // Add a constant for the cookie name
    private static final String SPRING_JWT_COOKIE_NAME = "springJwt";

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        SecurityContextHolder.clearContext();

        // Remove the JWT token cookie
        removeJwtCookie(response);

    }

    private void removeJwtCookie(HttpServletResponse response) {
        // Create a new cookie with the same name and set its value to null
        Cookie jwtCookie = new Cookie(SPRING_JWT_COOKIE_NAME, null);

        // Set the cookie to expire immediately
        jwtCookie.setMaxAge(0);

        // Set the cookie path to match the path used when creating the cookie
        jwtCookie.setPath("/"); // Assuming the cookie was set for the root path
        response.addCookie(jwtCookie);
    }
}

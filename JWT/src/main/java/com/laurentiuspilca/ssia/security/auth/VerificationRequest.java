package com.laurentiuspilca.ssia.security.auth;

import lombok.Data;

@Data
public class VerificationRequest {
    private String email;
    private String baseUrl; // Base URL for constructing verification link (e.g., "http://localhost:8080")
}

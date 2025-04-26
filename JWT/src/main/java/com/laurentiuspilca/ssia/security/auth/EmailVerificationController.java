package com.laurentiuspilca.ssia.security.auth;

import com.laurentiuspilca.ssia.entity.Users;
import com.laurentiuspilca.ssia.repository.UsersRepository;
import com.laurentiuspilca.ssia.security.jwt.JWTEmailVerificationTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class EmailVerificationController {

    private final JWTEmailVerificationTokenProvider tokenProvider;
    private final UsersRepository usersRepository;

    @PostMapping("/generate-verification-link")
    public ResponseEntity<?> generateVerificationLink(@RequestBody VerificationRequest request) {
        // Find the user by email
        Optional<Users> userOptional = usersRepository.findByEmail(request.getEmail());

        if (userOptional.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "User not found"));
        }

        Users user = userOptional.get();

        // If already verified, no need to generate link
        if (user.isVerified()) {
            return ResponseEntity.ok(Map.of("message", "Email already verified"));
        }

        // Generate verification token
        String token = tokenProvider.generateEmailVerificationToken(user.getEmail());

        // Create verification link
        String verificationLink = request.getBaseUrl() + "/api/auth/verify?token=" + token;

        return ResponseEntity.ok(Map.of(
                "message", "Verification link generated successfully",
                "verificationLink", verificationLink
        ));
    }

    @GetMapping("/verify")
    public ResponseEntity<?> verifyEmail(@RequestParam("token") String token) {
        if (!tokenProvider.validateToken(token)) {
            return ResponseEntity.badRequest().body(Map.of("message", "Invalid or expired verification token"));
        }

        String email = tokenProvider.getEmailFromToken(token);
        Optional<Users> userOptional = usersRepository.findByEmail(email);

        if (userOptional.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("message", "User not found"));
        }

        Users user = userOptional.get();
        user.setVerified(true);
        usersRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "Email verified successfully"));
    }
}

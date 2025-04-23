package com.laurentiuspilca.ssia.controllers;

import com.laurentiuspilca.ssia.entity.Users;
import com.laurentiuspilca.ssia.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UsersController {
    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/users")
    public ResponseEntity<Users> addUser(@RequestBody Users user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        Users savedUser = usersRepository.save(user);
        return ResponseEntity.ok(savedUser);
    }
}

package com.laurentiuspilca.ssia.controllers;

import com.laurentiuspilca.ssia.entity.Users;
import com.laurentiuspilca.ssia.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UsersController {
    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("")
    public ResponseEntity<Users> addUser(@RequestBody Users user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        Users savedUser = usersRepository.save(user);
        return ResponseEntity.ok(savedUser);
    }

    @GetMapping("/{id}")
//    @PreAuthorize("#id == authentication.principal.id")
    public ResponseEntity<Users> getUser(@PathVariable Long id) {
        Users user = usersRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        return ResponseEntity.ok(user);
    }

    @PutMapping("/{id}")
    @PreAuthorize("#id == authentication.principal.id")
    public ResponseEntity<Users> updateUser(@PathVariable Long id, @RequestBody Users user) {
        user.setId(id);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        Users savedUser = usersRepository.save(user);
        return ResponseEntity.ok(savedUser);
    }


}

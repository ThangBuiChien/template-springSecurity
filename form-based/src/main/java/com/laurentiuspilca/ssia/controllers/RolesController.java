package com.laurentiuspilca.ssia.controllers;

import com.laurentiuspilca.ssia.entity.Roles;
import com.laurentiuspilca.ssia.entity.Users;
import com.laurentiuspilca.ssia.repository.RolesRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RolesController {
    private final RolesRepository rolesRepository;

    @PostMapping("/roles")
    public ResponseEntity<Roles> addRole(@RequestBody Roles role) {
        Roles savedRole = rolesRepository.save(role);
        return ResponseEntity.ok(savedRole);
    }
}

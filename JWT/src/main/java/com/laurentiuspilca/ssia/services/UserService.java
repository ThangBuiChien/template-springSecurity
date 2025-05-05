package com.laurentiuspilca.ssia.services;

import com.laurentiuspilca.ssia.entity.Users;

import java.util.Optional;
import java.util.UUID;

public interface UserService {

    public UUID createRefreshToken(String username);

    public void invalidateRefreshToken(String username);

    public Optional<Users> findByRefreshToken(UUID refreshToken);

    public Optional<Users> findByUsername(String username);
}

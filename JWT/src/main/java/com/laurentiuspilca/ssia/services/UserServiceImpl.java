package com.laurentiuspilca.ssia.services;

import com.laurentiuspilca.ssia.entity.Users;
import com.laurentiuspilca.ssia.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    private final UsersRepository usersRepository;
    @Override
    public UUID createRefreshToken(String username) {
        Users user = usersRepository.findByUserName(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));

        user.generateNewRefreshToken();
        usersRepository.save(user);

        return user.getRefreshToken();
    }

    @Override
    public void invalidateRefreshToken(String username) {
        usersRepository.findByUserName(username).ifPresent(user -> {
            user.clearRefreshToken();
            usersRepository.save(user);
        });

    }

    @Override
    public Optional<Users> findByRefreshToken(UUID refreshToken) {
        return usersRepository.findByRefreshToken(refreshToken);
    }

    @Override
    public Optional<Users> findByUsername(String username) {
        return usersRepository.findByUserName(username);
    }
}

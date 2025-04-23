package com.laurentiuspilca.ssia.repository;

import com.laurentiuspilca.ssia.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UsersRepository extends JpaRepository<Users, Long> {

    Optional<Users> findByUserName(String userName);
}

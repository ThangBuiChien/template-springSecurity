package com.laurentiuspilca.ssia.security.user;

import com.laurentiuspilca.ssia.entity.Users;
import com.laurentiuspilca.ssia.repository.UsersRepository;
import com.laurentiuspilca.ssia.security.user.SecurityUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final UsersRepository usersRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user = usersRepository.findByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        return new SecurityUser(user);

    }
}

package com.laurentiuspilca.ssia.security.service;

import com.laurentiuspilca.ssia.entity.Roles;
import com.laurentiuspilca.ssia.entity.Users;
import com.laurentiuspilca.ssia.repository.RolesRepository;
import com.laurentiuspilca.ssia.repository.UsersRepository;
import com.laurentiuspilca.ssia.security.SecurityUser;
import com.laurentiuspilca.ssia.security.outh2.GithubOAuth2UserInfo;
import com.laurentiuspilca.ssia.security.outh2.GoogleOAuth2UserInfo;
import com.laurentiuspilca.ssia.security.outh2.OAuth2UserInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UsersRepository userRepository;
    private final RolesRepository rolesRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
            return processOAuth2User(userRequest, oAuth2User);
        } catch (Exception ex) {
            throw new OAuth2AuthenticationException(ex.getMessage());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo userInfo = getOAuth2UserInfo(registrationId, oAuth2User.getAttributes());

        // Find user by email from the OAuth provider
        Optional<Users> userOptional = userRepository.findByUserName(userInfo.getEmail());

        Users user;
        if (userOptional.isPresent()) {
            user = userOptional.get();
            // Update existing user with OAuth info
            user.setProvider(registrationId);
            user.setProviderId(userInfo.getId());
            user.setName(userInfo.getName());
            user.setImageUrl(userInfo.getImageUrl());
            user = userRepository.save(user);
        } else {
            // Create a new user with OAuth info
            user = registerNewUser(registrationId, userInfo);
        }

        return SecurityUser.create(user, oAuth2User.getAttributes());
    }

    private OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equalsIgnoreCase("google")) {
            return new GoogleOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase("github")) {
            return new GithubOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationException("Login with " + registrationId + " is not supported yet");
        }
    }

    private Users registerNewUser(String provider, OAuth2UserInfo userInfo) {
        Users user = new Users();

        user.setUserName(userInfo.getEmail());
        user.setEmail(userInfo.getEmail());
        user.setName(userInfo.getName());
        user.setProvider(provider);
        user.setProviderId(userInfo.getId());
        user.setImageUrl(userInfo.getImageUrl());
        user.setEnabled(true);
        user.setPassword(""); // OAuth2 users don't need a password

        // Assign default USER role
        Roles userRole = rolesRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Role not found"));
        Set<Roles> roles = new HashSet<>();
        roles.add(userRole);
        user.setRoles(roles);

        return userRepository.save(user);
    }

}

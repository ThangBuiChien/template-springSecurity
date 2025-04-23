package com.laurentiuspilca.ssia.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String userName;
    private String password;

    // Add these new fields for OAuth2
    private String email;
    private String name;
    private String provider; // "google", "github", etc.
    private String providerId; // ID in the provider's system
    private String imageUrl;
    private boolean enabled = true;

    @ManyToMany(fetch = FetchType.EAGER) // Load roles with user
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Roles> roles; // Use Set to avoid duplicate roles
}

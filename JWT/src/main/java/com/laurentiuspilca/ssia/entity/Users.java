package com.laurentiuspilca.ssia.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;
import java.util.UUID;

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

    private String email;
    private boolean isVerified = false;

    @ManyToMany(fetch = FetchType.EAGER) // Load roles with user
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Roles> roles; // Use Set to avoid duplicate roles

    @Column(name = "refresh_token")
    private UUID refreshToken;

    public void generateNewRefreshToken() {
        this.refreshToken = UUID.randomUUID();
    }

    public void clearRefreshToken() {
        this.refreshToken = null;
    }
}

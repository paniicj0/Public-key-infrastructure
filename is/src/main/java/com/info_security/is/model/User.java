package com.info_security.is.model;

import com.info_security.is.dto.UserDto;
import com.info_security.is.enums.UserRole;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true)
    private String email;
    @Column(nullable = false, unique = true)
    private String password;
    @Column(nullable = false)
    private String firstName;
    @Column(nullable = false)
    private String lastName;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole role;
    @Column(nullable = false, unique = false)
    private boolean isActive;

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private Activation activation;

    @ManyToOne
    @JoinColumn(name = "organization_id", nullable = false)
    private Organization organization;

    public boolean isActive() {
        return isActive;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // pošto u @PreAuthorize koristiš hasAnyAuthority('ADMIN','CA','USER'),
        // authority string treba da bude baš "ADMIN"/"CA"/"USER"
        return List.of(new SimpleGrantedAuthority(role.name()));
        // Ako bi koristio hasAnyRole(...) onda bi ovde bilo: "ROLE_"+role.name()
    }

    @Override
    public String getUsername() {
        return email;     // VAŽNO: username je tvoj email
    }


    public User(UserDto userDto) {
        this.email = userDto.getEmail();
        this.password = userDto.getPassword();
        this.firstName = userDto.getFirstName();
        this.lastName = userDto.getLastName();
        this.role = userDto.getRole();
        this.isActive = userDto.isActive();
    }

    public User (Long id, String email, String password, String firstName, String lastName, UserRole role, boolean isActive) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.firstName = firstName;
        this.lastName = lastName;
        this.role = role;
        this.isActive = isActive;
    }

    public Long getId() {
        return id;
    }
    public UserRole getRole() {
        return role;
    }
    public String getEmail() {
        return email;
    }
    public String getFirstName() {
        return firstName;
    }
    public String getLastName() {
        return lastName;
    }

    public String getPassword() {
        return password;
    }

    public void setId(Long id) { this.id = id; }
    public void setEmail(String email) { this.email = email; }
    public void setPassword(String password) { this.password = password; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
    public void setRole(UserRole role) { this.role = role; } // 👈 OVO JE KLJUČNO
    public void setActive(boolean active) { isActive = active; }
    public void setActivation(Activation activation) { this.activation = activation; }
    public void setOrganization(Organization organization) { this.organization = organization;}
}

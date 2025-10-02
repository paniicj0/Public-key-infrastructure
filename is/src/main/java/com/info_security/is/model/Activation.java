package com.info_security.is.model;

import jakarta.persistence.*;
import lombok.*;
import org.antlr.v4.runtime.misc.NotNull;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Setter
@Getter
public class Activation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @OneToOne
    //@JsonBackReference(value = "user-activation")
    private User user;

    @NotNull
    private LocalDateTime creationDate;

    @NotNull
    private LocalDateTime expirationDate;

    @Column(name = "token_hash", length = 64, unique = true)
    private String tokenHash;

    // ✅ Kada je link iskorišćen (null dok nije)
    @Column(name = "used_at")
    private LocalDateTime usedAt;

    public boolean isExpired() { return LocalDateTime.now().isAfter(expirationDate); }
    public boolean isUsed() { return usedAt != null; }
}

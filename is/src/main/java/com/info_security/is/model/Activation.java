package com.info_security.is.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.antlr.v4.runtime.misc.NotNull;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Activation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @NotNull
    @OneToOne
    //@JsonBackReference(value = "user-activation")
    private User user;

    @NotNull
    private LocalDateTime creationDate;

    @NotNull
    private LocalDateTime expirationDate;


    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expirationDate);
    }


}

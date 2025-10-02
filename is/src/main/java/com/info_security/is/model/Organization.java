package com.info_security.is.model;

import jakarta.persistence.Entity;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Organization {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true)
    private String name;

    @Column(name = "org_key_blob", columnDefinition = "TEXT")
    private String orgKeyBlob; // {"v":1,"alg":"AES-256-GCM","iv":"...","ct":"...","tag":"..."}

}

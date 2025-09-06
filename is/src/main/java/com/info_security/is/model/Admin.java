package com.info_security.is.model;

import com.info_security.is.dto.AdminDto;
import com.info_security.is.dto.CaDto;
import jakarta.persistence.Entity;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Entity
@AllArgsConstructor
@NoArgsConstructor
public class Admin extends User{

    public Admin(AdminDto adminDto) {
        this.setId(adminDto.getId());
        this.setEmail(adminDto.getEmail());
        this.setPassword(adminDto.getPassword());
        this.setFirstName(adminDto.getFirstName());
        this.setLastName(adminDto.getLastName());
        this.setRole(adminDto.getRole());
    }
}

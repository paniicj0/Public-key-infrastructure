package com.info_security.is.model;

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
public class CA extends User{

    public CA(CaDto caDto) {
        this.setId(caDto.getId());
        this.setEmail(caDto.getEmail());
        this.setPassword(caDto.getPassword());
        this.setFirstName(caDto.getFirstName());
        this.setLastName(caDto.getLastName());
        this.setRole(caDto.getRole());
    }

}

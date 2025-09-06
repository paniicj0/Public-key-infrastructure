package com.info_security.is.dto;

import com.info_security.is.model.Admin;
import com.info_security.is.model.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@NoArgsConstructor
@AllArgsConstructor
public class AdminDto extends UserDto{

    public AdminDto(Admin user){
        this.id = user.getId();
        this.email = user.getEmail();
        this.password = user.getPassword();
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
        this.role = user.getRole();
        this.isActive = user.isActive();
    }
}

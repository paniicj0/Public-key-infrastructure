package com.info_security.is.dto;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.info_security.is.enums.UserRole;
import com.info_security.is.model.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.stereotype.Component;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "role")
@JsonSubTypes({
        @JsonSubTypes.Type(value = AdminDto.class, name = "ADMIN"),
        @JsonSubTypes.Type(value = CaDto.class, name = "CA")
})
@Getter
@Setter
@Component
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {

    protected Long id;
    protected String email;
    protected String password;
    protected String firstName;
    protected String lastName;
    protected UserRole role;
    protected boolean isActive;

    public UserDto(User user){
        this.id = user.getId();
        this.email = user.getEmail();
        this.password = user.getPassword();
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
        this.role = user.getRole();
        this.isActive = user.isActive();
    }
}

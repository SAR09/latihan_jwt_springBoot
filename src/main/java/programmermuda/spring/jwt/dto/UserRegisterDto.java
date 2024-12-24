package programmermuda.spring.jwt.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

public record UserRegisterDto(
        @NotEmpty(message = "Username must not be empty")
        String username,
        String userMobileNo,
        @NotEmpty(message = "User email must not be empty")
        @Email(message = "Invalid email format")
        String userEmail,
        @NotEmpty(message = "User password must not be empty")
        String userPassword,
        @NotEmpty(message = "User role must not be empty")
        String userRole
) {
}

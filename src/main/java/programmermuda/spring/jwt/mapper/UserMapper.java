package programmermuda.spring.jwt.mapper;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import programmermuda.spring.jwt.dto.UserRegisterDto;
import programmermuda.spring.jwt.entity.User;

@Component
public class UserMapper {

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User convertToEntity(UserRegisterDto userRegisterDto){
        User user = new User();
        user.setUsername(userRegisterDto.username());
        user.setEmail(userRegisterDto.userEmail());
        user.setMobileNumber(userRegisterDto.userMobileNo());
        user.setRoles(userRegisterDto.userRole());
        user.setPassword(passwordEncoder.encode(userRegisterDto.userPassword()));
        return user;
    }

}

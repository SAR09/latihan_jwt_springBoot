package programmermuda.spring.jwt.runner;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import programmermuda.spring.jwt.entity.User;
import programmermuda.spring.jwt.repository.UserRepository;

import java.util.List;


@Component
@Slf4j
public class InitialUser implements CommandLineRunner {


    private final UserRepository userRepository;


    private final PasswordEncoder passwordEncoder;

    public InitialUser(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        User manager = new User();
        manager.setUsername("Manager");
        manager.setPassword(passwordEncoder.encode("password"));
        manager.setRoles("ROLE_MANAGER");
        manager.setEmail("manager@manager.com");

        User admin = new User();
        admin.setUsername("Admin");
        admin.setPassword(passwordEncoder.encode("password"));
        admin.setRoles("ROLE_ADMIN");
        admin.setEmail("admin@admin.com");

        User user = new User();
        user.setUsername("User");
        user.setPassword(passwordEncoder.encode("password"));
        user.setRoles("ROLE_USER");
        user.setEmail("user@user.com");

        userRepository.saveAll(List.of(manager, admin, user));
    }
}

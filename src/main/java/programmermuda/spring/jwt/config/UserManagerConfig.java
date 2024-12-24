package programmermuda.spring.jwt.config;


import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import programmermuda.spring.jwt.repository.UserRepository;

@Service
public class UserManagerConfig implements UserDetailsService {

    private final UserRepository userRepository;

    public UserManagerConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository
                .findByEmail(email)
                .map(UserConfig::new)
                .orElseThrow(()-> new UsernameNotFoundException("User Email : " +email+" does not exist"));
    }
}

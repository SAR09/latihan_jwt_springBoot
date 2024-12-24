package programmermuda.spring.jwt.jwtAuth;

import jakarta.persistence.Column;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import programmermuda.spring.jwt.config.UserConfig;
import programmermuda.spring.jwt.repository.UserRepository;

import java.time.Instant;
import java.util.Objects;

@Component
public class JwtTokenUtils {

    @Autowired
    private UserRepository userRepository;

    public String getUsername(Jwt jwtToken){
        return jwtToken.getSubject();
    }

    public boolean isTokenValid(Jwt jwtToken, UserDetails userDetails){
        final String username = getUsername(jwtToken);
        boolean isTokenExpired = getIfTokenIsExpired(jwtToken);
        boolean isTokenUserSameAsDatabase = username.equals(userDetails.getUsername());
        return !isTokenExpired && isTokenUserSameAsDatabase;
    }

    private boolean getIfTokenIsExpired(Jwt jwtToken) {
        return Objects.requireNonNull(jwtToken.getExpiresAt().isBefore(Instant.now()));
    }

    public UserDetails userDetails(String email){
        return userRepository
                .findByEmail(email)
                .map(UserConfig::new)
                .orElseThrow(() -> new UsernameNotFoundException("User Email : " +email + " does not exist"));
    }

}

package programmermuda.spring.jwt.service.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import programmermuda.spring.jwt.dto.TokenType;
import programmermuda.spring.jwt.repository.RefreshTokenRepository;

@Service
public class LogoutHandlerService implements LogoutHandler {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (!authHeader.startsWith(TokenType.Bearer.name())){
            return;
        }

        final String refreshToken = authHeader.substring(7);

        var storeRefreshToken = refreshTokenRepository.findByRefreshToken(refreshToken)
                .map(token ->{
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                    return token;
                })
                .orElse(null);
    }
}

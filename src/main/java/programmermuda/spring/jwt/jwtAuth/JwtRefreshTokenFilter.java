package programmermuda.spring.jwt.jwtAuth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;
import programmermuda.spring.jwt.config.RSAKeyRecord;
import programmermuda.spring.jwt.repository.RefreshTokenRepository;

import java.io.IOException;

public class JwtRefreshTokenFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAccessTokenFilter.class);

    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;
    private final RefreshTokenRepository refreshTokenRepository;

    // Constructor Injection
    public JwtRefreshTokenFilter(RSAKeyRecord rsaKeyRecord, JwtTokenUtils jwtTokenUtils, RefreshTokenRepository refreshTokenRepository) {
        this.rsaKeyRecord = rsaKeyRecord;
        this.jwtTokenUtils = jwtTokenUtils;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        try {
            log.info("[JwtRefreshTokenFilter:doFilterInternal] :: Started");
            log.info("[JwtRefreshTokenFilter:doFilterInternal] Filtering the Http Request : {}", request.getRequestURI());

            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();

            if (!authHeader.startsWith("Bearer")){
                filterChain.doFilter(request, response);
                return;
            }

            final String token = authHeader.substring(7);
            final Jwt jwtRefreshToken = jwtDecoder.decode(token);

            final String username = jwtTokenUtils.getUsername(jwtRefreshToken);

            if (!username.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null){
                //check if refreshToken isPresent in database and is valid
                var isRefreshTokenValidInDatabase = refreshTokenRepository.findByRefreshToken(jwtRefreshToken.getTokenValue())
                        .map(refreshToken -> !refreshToken.isRevoked())
                        .orElse(false);

                UserDetails userDetails = jwtTokenUtils.userDetails(username);
                if (jwtTokenUtils.isTokenValid(jwtRefreshToken, userDetails) && isRefreshTokenValidInDatabase){
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                    UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(createdToken);
                    SecurityContextHolder.setContext(securityContext);
                }
            }
            log.info("[JwtRefreshTokenFilter:doFilterInternal] Completed");
            filterChain.doFilter(request, response);
        }catch (JwtValidationException jwtValidationException){
            log.error("[JwtRefreshTokenFilter:doFilterInternal] Exception due to : {}", jwtValidationException.getMessage());
            throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, jwtValidationException.getMessage());
        }

    }
}

package programmermuda.spring.jwt.jwtAuth;

import programmermuda.spring.jwt.dto.TokenType;
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

import java.io.IOException;

public class JwtAccessTokenFilter extends OncePerRequestFilter {

    @Autowired
    private Logger log = LoggerFactory.getLogger(JwtAccessTokenFilter.class);

    @Autowired
    private RSAKeyRecord rsaKeyRecord;

    @Autowired
    private JwtTokenUtils jwtTokenUtils;

    public JwtAccessTokenFilter(RSAKeyRecord rsaKeyRecord, JwtTokenUtils jwtTokenUtils) {
        this.rsaKeyRecord = rsaKeyRecord;
        this.jwtTokenUtils = jwtTokenUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            log.info("[JwtAccessTokenFilter:doFilterInternal] :: Started");

            log.info("[JwtAccessTokenFilter:doFilterInternal] Filtering the Http Request : {}", request.getRequestURI());

            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();

            if (!authHeader.startsWith(TokenType.Bearer.name())){
                filterChain.doFilter(request, response);
                return;
            }

            final String token = authHeader.substring(7);
            final Jwt jwtToken = jwtDecoder.decode(token);

            final String username = jwtTokenUtils.getUsername(jwtToken);

            if (!username.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null){

                UserDetails userDetails = jwtTokenUtils.userDetails(username);
                if (jwtTokenUtils.isTokenValid(jwtToken, userDetails)){
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

            log.info("[JwtAccessTokenFilter:doFilter] Completed");

            filterChain.doFilter(request, response);

        }catch (JwtValidationException jwtValidationException){
            log.error("[JwtAccessTokenFilter:doFilterInternal] Exeption due to : {}", jwtValidationException.getMessage());
            throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, jwtValidationException.getMessage());
        }
    }
}

package programmermuda.spring.jwt.service.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import programmermuda.spring.jwt.dto.AuthResponseDto;
import programmermuda.spring.jwt.dto.TokenType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import programmermuda.spring.jwt.dto.UserRegisterDto;
import programmermuda.spring.jwt.entity.RefreshToken;
import programmermuda.spring.jwt.entity.User;
import programmermuda.spring.jwt.jwtAuth.JwtTokenGenerator;
import programmermuda.spring.jwt.mapper.UserMapper;
import programmermuda.spring.jwt.repository.RefreshTokenRepository;
import programmermuda.spring.jwt.repository.UserRepository;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Optional;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtTokenGenerator jwtTokenGenerator;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserMapper userMapper;

    public AuthResponseDto getJwtTokenAfterAuthentication(Authentication authentication, HttpServletResponse response){
        try {
            var user = userRepository.findByEmail(authentication.getName())
                    .orElseThrow(()->{
                        log.error("[AuthService:userSignInAuth] User : {} not found", authentication.getName());
                        return new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND");
                    });

            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            saveUserRefreshToken(user, refreshToken);
            createRefreshToken(response, refreshToken);
            log.info("[AuthService:userSignInAuth] Access token for user: {}, has been generated", user.getUsername());
            return AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(15 * 60)
                    .username(user.getUsername())
                    .tokenType(TokenType.Bearer)
                    .build();
        }catch (Exception exception){
            log.error("[AuthService:userSigInAuth]Exception while authenticating the user due to : " + exception.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please Try Again");
        }
    }

    private Cookie createRefreshToken(HttpServletResponse response, String refreshToken) {
        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(15 * 24 * 60); // in second
        response.addCookie(refreshTokenCookie);
        return refreshTokenCookie;
    }

    private void saveUserRefreshToken(User user, String refreshToken){
        var refreshTokenEntity = RefreshToken.builder()
                .setUser(user)
                .setRefreshToken(refreshToken)
                .setRevoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);
    }

    public Object getAccessTokenUsingRefreshToken(String authorizationHeader){

        if (!authorizationHeader.startsWith(TokenType.Bearer.name())){
            return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please verify your token type");
        }

        final String refreshToken = authorizationHeader.substring(7);

        //Find refresh token from database and should not be revoked : Same thing can be done through filter.
        var refreshTokenEntity =  refreshTokenRepository.findByRefreshToken(refreshToken)
                .filter(tokens -> !tokens.isRevoked())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Refresh token revoked"));

        User user = refreshTokenEntity.getUser();

        //Now create the Authentication object
        Authentication authentication = createAuthenticationObject(user);

        //use the authentication object to generate new accessToken as the Authentication object that we will have may not contain correct role
        String accessToken = jwtTokenGenerator.generateAccessToken(authentication);

        return  AuthResponseDto.builder()
                .accessToken(accessToken)
                .accessTokenExpiry(5*60)
                .username(user.getUsername())
                .tokenType(TokenType.Bearer)
                .build();
    }

    private static Authentication createAuthenticationObject(User user){
        //Extract user details from UserDetailsEntity
        String username = user.getEmail();
        String password = user.getPassword();
        String roles = user.getRoles();

        // Extract authorities from roles (comma-separated)
        String[] roleArray = roles.split(",");
        GrantedAuthority[] authorities = Arrays.stream(roleArray)
                .map(role -> (GrantedAuthority) role::trim)
                .toArray(GrantedAuthority[]::new);

        return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList(authorities));
    }

    public AuthResponseDto registerUser(UserRegisterDto userRegisterDto, HttpServletResponse httpServletResponse){

        try {
            log.info("[AuthService:registerUser]User Registration started with :::{}", userRegisterDto);

            Optional<User> user = userRepository.findByEmail(userRegisterDto.userEmail());
            if (user.isPresent()){
                throw new Exception("User Already Exist");
            }

            User userDetailsEntity = userMapper.convertToEntity(userRegisterDto);
            Authentication authentication = createAuthenticationObject(userDetailsEntity);

            //generate a jwt token
            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            User savedUserDetails = userRepository.save(userDetailsEntity);
            saveUserRefreshToken(userDetailsEntity, refreshToken);

            createRefreshTokenCookie(httpServletResponse, refreshToken);

            log.info("[AuthService:registerUser] User : {} Successfully registered", savedUserDetails.getUsername());
            return AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(5 * 60)
                    .username(savedUserDetails.getUsername())
                    .tokenType(TokenType.Bearer)
                    .build();
        }catch (Exception exception){
            log.error("[AuthService:registerUser]Exception while registering the user due to : ", exception.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, exception.getMessage());
        }
    }

    private Cookie createRefreshTokenCookie(HttpServletResponse response, String refreshToken){
        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60); //in second
        response.addCookie(refreshTokenCookie);
        return refreshTokenCookie;
    }



}

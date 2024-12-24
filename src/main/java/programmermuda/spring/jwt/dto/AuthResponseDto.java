package programmermuda.spring.jwt.dto;


import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthResponseDto {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("access_token_expiry")
    private int accessTokenExpiry;

    @JsonProperty("token_type")
    private TokenType tokenType;

    @JsonProperty("user_name")
    public String username;

    public AuthResponseDto(String accessToken, int accessTokenExpiry, TokenType tokenType, String username) {
        this.accessToken = accessToken;
        this.accessTokenExpiry = accessTokenExpiry;
        this.tokenType = tokenType;
        this.username = username;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public int getAccessTokenExpiry() {
        return accessTokenExpiry;
    }

    public void setAccessTokenExpiry(int accessTokenExpiry) {
        this.accessTokenExpiry = accessTokenExpiry;
    }

    public TokenType getTokenType() {
        return tokenType;
    }

    public void setTokenType(TokenType tokenType) {
        this.tokenType = tokenType;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public static class Builder{
        private String accessToken;
        public int accessTokenExpiry;
        private TokenType tokenType;
        private String username;

        public Builder accessToken(String accessToken){
            this.accessToken = accessToken;
            return this;
        }

        public Builder accessTokenExpiry(int accessTokenExpiry) {
            this.accessTokenExpiry = accessTokenExpiry;
            return this;
        }

        public Builder tokenType(TokenType tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public AuthResponseDto build() {
            return new AuthResponseDto(accessToken, accessTokenExpiry, tokenType, username);
        }

    }

    public static Builder builder() {
        return new Builder();
    }
}

package programmermuda.spring.jwt.entity;

import jakarta.persistence.*;
import programmermuda.spring.jwt.dto.AuthResponseDto;

@Entity
public class RefreshToken {

    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "refresh_token", nullable = false, length = 10000)
    private String refreshToken;

    private boolean revoked;

    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private User user;

    // Constructor
    public RefreshToken(Long id, String refreshToken, boolean revoked, User user) {
        this.id = id;
        this.refreshToken = refreshToken;
        this.revoked = revoked;
        this.user = user;
    }

    // Default Constructor
    public RefreshToken() {
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    // Builder Class
    public static class Builder {
        private Long id;
        private String refreshToken;
        private boolean revoked;
        private User user;

        public Builder setId(Long id) {
            this.id = id;
            return this;
        }

        public Builder setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        public Builder setRevoked(boolean revoked) {
            this.revoked = revoked;
            return this;
        }

        public Builder setUser(User user) {
            this.user = user;
            return this;
        }

        public RefreshToken build() {
            return new RefreshToken(id, refreshToken, revoked, user);
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}

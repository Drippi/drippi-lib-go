package crypto

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"regexp"
)

const (
	// UserIdKey is the key for user ID in JWT Claims mapping
	UserIdKey = "user_id"
	// UserLevelKey is the key for user level in JWT Claims mapping
	UserLevelKey = "level"

	// JWTEnvVar is the environment variable name where the JWT secret is stored
	JWTEnvVar = "JWT_SHARED_SECRET"
	// JWTTestSecret is the secret used when none is provided,
	// or the application is running in a test environment
	JWTTestSecret = "drippi-test-secret"
)

// GetJWTSecretKey retrieves the secret key from the environment variable JWTEnvVar
// if no value is set or application is running in testing env, JWTTestSecret is used.
func GetJWTSecretKey(env string) string {
	secret := os.Getenv(JWTEnvVar)
	if secret == "" || env == "test"{
		secret = JWTTestSecret
	}
	return secret
}

// ValidateJWTToken validates an encoded JWT token with the given secret.
func ValidateJWTToken(encodedToken string, secret string) (*jwt.Token, error) {
	return jwt.Parse(encodedToken, func(token *jwt.Token) (interface{}, error) {
		if _, isvalid := token.Method.(*jwt.SigningMethodHMAC); !isvalid {
			return nil, fmt.Errorf("invalid token, incorrect algorithm: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})
}

// GetJWTAuthMiddleware create a gin.HandlerFunc to be used as a middleware that
// will validate JWT's passed in the Authorization header in the format `Bearer [JWT]`
// with the given secret.
func GetJWTAuthMiddleware(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		bearer := c.GetHeader("Authorization")
		if m, err := regexp.MatchString("Bearer .+", bearer); !m || err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authentication needed; invalid JWT"})
			c.Abort()
			return
		}

		jwtToken := bearer[7:]
		token, err := ValidateJWTToken(jwtToken, secret)
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authentication needed; invalid JWT"})
			c.Abort()
			return
		}
		c.Set("token", token)
		c.Next()
	}
}

package crypto

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/assert/v2"
	"github.com/stretchr/testify/http"
	"net/http/httptest"
	"os"
	"testing"
)

const (
	testJWTKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjowLCJsZXZlbCI6MX0.xxnZlhpctgl9jsgNEmriSEuAi5F0Vw_r1yfczrqikPc"
	testJWTUserId = float64(0)
	testJWTUserLevel = float64(1)
)


func TestGetJWTSecretKey(t *testing.T) {
	expected := "test-secret"
	var err error

	err = os.Setenv(JWTEnvVar, expected)
	if err != nil {
		t.Errorf("Failed to set env variable")
	}
	assert.Equal(t, GetJWTSecretKey("prod"), expected)

	assert.Equal(t, GetJWTSecretKey("test"), JWTTestSecret)

	err = os.Unsetenv(JWTEnvVar)
	if err != nil {
		t.Errorf("Failed to unset env variable")
	}
	assert.Equal(t, GetJWTSecretKey("dev"), JWTTestSecret)
}

func TestValidateJWTToken(t *testing.T) {
	token, err := ValidateJWTToken(testJWTKey, JWTTestSecret)
	if err != nil {
		t.Fatal("Unable to validate token")
		return
	}

	if !token.Valid {
		t.Fatal("Token is invalid")
	}

	claims := token.Claims.(jwt.MapClaims)
	assert.Equal(t, claims[UserIdKey], testJWTUserId)
	assert.Equal(t, claims[UserLevelKey], testJWTUserLevel)

	_, err = ValidateJWTToken("invalid token!", JWTTestSecret)
	if err == nil {
		t.Fatalf("Validated invalid token")
	}
}

func TestGetJWTAuthMiddleware(t *testing.T) {

	gin.SetMode(gin.TestMode)

	f := GetJWTAuthMiddleware(JWTTestSecret)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("POST", "/test/endpoint", nil)
	c.Request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", testJWTKey))

	f(c)

	token, exists := c.Get("token")
	if !exists {
		t.Fatal("Unable to get token after auth middleware")
	}
	if !token.(*jwt.Token).Valid {
		t.Fatal("Given invalid token")
	}

	c, _ = gin.CreateTestContext(new(http.TestResponseWriter))
	c.Request = httptest.NewRequest("POST", "/test/endpoint", nil)
	c.Request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", "invalid jwt"))
	f(c)
	if !c.IsAborted() {
		t.Fatal("Handler did not abort")
	}

}
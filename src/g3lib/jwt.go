package g3lib

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const G3_JWT_SECRET   = "G3_JWT_SECRET"         // JWT signature secret.
const G3_JWT_LIFETIME = "G3_JWT_LIFETIME"       // JWT token lifetime in minutes.

// Internally called to get the JWT secret from the environment.
func GetJwtSecret() (interface{}, error) {
	jwtSecretStr := os.Getenv(G3_JWT_SECRET)
	if jwtSecretStr == "" {
		return nil, errors.New("missing environment variable: " + G3_JWT_SECRET)
	}
	return []byte(jwtSecretStr), nil
}

// Internally called to get the JWT token lifetime from the environment.
func GetJwtLifetime() (int, error) {
	jwtLifetimeStr := os.Getenv(G3_JWT_LIFETIME)
	if jwtLifetimeStr == "" {
		return 0, errors.New("missing environment variable: " + G3_JWT_LIFETIME)
	}
	return strconv.Atoi(jwtLifetimeStr)
}

// Generate a JWT for a logged in user.
func GenerateJwt(userid int) (string, error) {
	jwtLifetime, err := GetJwtLifetime()
	if err != nil {
		return "", err
	}
	return GenerateTemporaryJwt(userid, time.Minute * time.Duration(jwtLifetime))
}

// Create a temporary JWT for specific operations.
func GenerateTemporaryJwt(userid int, timelimit time.Duration) (string, error) {
	jwtSecret, err := GetJwtSecret()
	if err != nil {
		return "", err
	}
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid": userid,
		"iat": now.Unix(),
		"exp": now.Add(timelimit).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}
	_, err = ValidateJwt(tokenString)	// paranoid programming :)
	return tokenString, err
}

// Get the user ID from a JWT, but only if it is valid.
func ValidateJwt(token string) (int, error) {
	if token == "" {
		return -1, errors.New("missing JWT token")
	}
	claims := jwt.MapClaims{}
	tkn, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		alg := fmt.Sprintf("%v", token.Header["alg"])
		if alg != "HS256" {
			return nil, errors.New("unexpected signing method: " + alg)
		}
		return GetJwtSecret()
	})
	if err != nil {
		return -1, err
	}
	if !tkn.Valid {
		return -1, errors.New("invalid JWT token")
	}

	exp, ok := claims["exp"]
	if !ok {
		return -1, errors.New("missing exp property in JWT")
	}
	var expFloat float64
	expFloat, ok = exp.(float64)
	if !ok {
		return -1, errors.New("invalid exp property in JWT")
	}
	if time.Now().Unix() > int64(expFloat) {
		return -1, errors.New("expired JWT token")
	}
	useridAny, ok := claims["uid"]
	if !ok {
		return -1, errors.New("missing uid property in JWT")
	}
	useridfloat, ok := useridAny.(float64)
	if !ok {
		return -1, errors.New("invalid uid property in JWT")
	}
	return int(useridfloat), nil
}

// Refresh a JWT token for an already logged in user.
func RefreshJwt(token string) (string, error) {
	userid, err := ValidateJwt(token)
	if err != nil {
		return "", err
	}
	return GenerateJwt(userid)
}

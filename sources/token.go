package utils

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func GetUserId(c *gin.Context) (int32, error) {

	bearerToken := c.Request.Header.Get("Authorization")
	tokenString := ""

	if len(strings.Split(bearerToken, " ")) == 2 {
		tokenString = strings.Split(bearerToken, " ")[1]
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token format"})
		return 0, errors.New("invalid token")
	}

	tokenPure, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("secret_key")), nil
	})

	if err != nil {
		return 0, err
	}

	if claims, ok := tokenPure.Claims.(jwt.MapClaims); ok && tokenPure.Valid {
		userID, _ := claims["user_id"].(float64)
		return int32(userID), nil
	} else {
		return 0, errors.New("invalid token")
	}
}

func GetUserUsername(c *gin.Context) (string, error) {

	bearerToken := c.Request.Header.Get("Authorization")
	tokenString := ""

	if len(strings.Split(bearerToken, " ")) == 2 {
		tokenString = strings.Split(bearerToken, " ")[1]
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token format"})
		return "", errors.New("invalid token")
	}

	tokenPure, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("secret_key")), nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := tokenPure.Claims.(jwt.MapClaims); ok && tokenPure.Valid {
		username, _ := claims["username"].(string)
		return username, nil
	} else {
		return "", errors.New("invalid username")
	}
}

func JwtAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := TokenValid(c)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

func TokenValid(c *gin.Context) error {
	tokenString, err := ExtractToken(c)
	if err != nil {
		return err
	}
	if tokenString == os.Getenv("ADM_TOKEN") {
		return nil
	}
	if tokenString == "" {
		return errors.New("no token given")
	}
	_, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("secret_key")), nil
	})
	if err != nil {
		return err
	}
	return nil
}

func ExtractToken(c *gin.Context) (string, error) {
	token := c.Query("token")
	if token != "" {
		return token, nil
	}
	bearerToken := c.Request.Header.Get("Authorization")
	if bearerToken == "" {
		return "", errors.New("No Authorization header provided")
	}
	if len(strings.Split(bearerToken, " ")) == 2 {
		return strings.Split(bearerToken, " ")[1], nil
	}
	return "", errors.New("Invalid Authorization header format")
}
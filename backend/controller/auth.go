package controller

import (
	"net/http"

	"github.com/GITTIIII/sa-66-example/entity"
	"github.com/GITTIIII/sa-66-example/service"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type LoginPayload struct {
	Email    string `json:"email"` //set varible email
	Password string `json:"password"`
}

// logintoken response
type LoginResponse struct {
	Token string `json:"token"`
	ID    uint   `json:"id"`
}

// get info from user email and password
func Login(c *gin.Context) {
	var payload LoginPayload
	var user entity.User

	if error := c.ShouldBindJSON(&payload); error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": error})
		return
	}

	// find user from email
	if error := entity.DB().Raw("SELECT * FROM users WHERE email = ?", payload.Email).Scan(&user).Error; error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": error})
		return
	}

	//check password
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(payload.Password))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password incorrect"})
		return
	}

	//format token
	jwtWrapper := service.JwtWrapper{
		SecretKey:       "ABC",
		Issuer:          "AuthService",
		ExpirationHours: 24,
	}

	signedToken, err := jwtWrapper.GenerateToken(user.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "error generating token"})
		return
	}

	tokenResponse := LoginResponse{
		Token: signedToken,
		ID:    user.ID,
	}

	c.JSON(http.StatusOK, gin.H{"data": tokenResponse})

}

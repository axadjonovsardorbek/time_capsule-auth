package handler

import (
	ap "auth/genproto"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt"
	_ "github.com/swaggo/swag"
	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
)

// Register godoc
// @Summary Register a new user
// @Description Register a new user
// @Tags auth
// @Accept json
// @Produce json
// @Param user body ap.UsersRegister true "User registration request"
// @Success 201 {object} string "User registered"
// @Failure 400 {object} string "Invalid request payload"
// @Failure 500 {object} string "Server error"
// @Router /register [post]
func (h *Handler) Register(c *gin.Context) {
	var req ap.UsersRegister

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server error"})
		return
	}
	req.Password = string(hashedPassword)

	// _, err = h.User.Register(context.Background(), &req)

	input, err := json.Marshal(&req)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return 
	}
	err = h.Producer.ProduceMessages("user", input)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered"})
}

// Login godoc
// @Summary Login a user
// @Description Authenticate user with email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param credentials body ap.UsersLogin true "User login credentials"
// @Success 200 {object} ap.Tokens "JWT tokens"
// @Failure 400 {object} string "Invalid request payload"
// @Failure 401 {object} string "Invalid email or password"
// @Router /login [post]
func (h *Handler) Login(c *gin.Context) {
	var req ap.UsersLogin

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := h.User.Login(context.Background(), &req)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, res)
}

// GetProfile godoc
// @Summary Get user profile
// @Description Get the profile of the authenticated user
// @Tags user
// @Accept json
// @Produce json
// @Success 200 {object} ap.UsersProfile
// @Failure 401 {object} string "Unauthorized"
// @Failure 404 {object} string "User not found"
// @Failure 500 {object} string "Server error"
// @Security BearerAuth
// @Router /profile [get]
func (h *Handler) Profile(c *gin.Context) {
	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	username := claims.(jwt.MapClaims)["username"].(string)

	user, err := h.User.Profile(context.Background(), &ap.UsersProfileReq{Username: username})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// GetSettings godoc
// @Summary Get user settings
// @Description Get the settings of the authenticated user
// @Tags user
// @Accept json
// @Produce json
// @Success 200 {object} ap.UsersSettings
// @Failure 401 {object} string "Unauthorized"
// @Failure 404 {object} string "User settings not found"
// @Failure 500 {object} string "Server error"
// @Security BearerAuth
// @Router /settings [get]
func (h *Handler) Settings(c *gin.Context) {
	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	username := claims.(jwt.MapClaims)["username"].(string)

	res, err := h.User.Settings(context.Background(), &ap.UsersProfileReq{Username: username})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if res == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User settings not found"})
		return
	}

	c.JSON(http.StatusOK, res)
}

// UpdateProfile godoc
// @Summary Update user profile
// @Description Update the profil of the authenticated user
// @Tags user
// @Accept json
// @Produce json
// @Param full_name query string false "FullName"
// @Param date_of_birth query string false "DateOfBirth"
// @Success 200 {object} string "User profile updated"
// @Failure 401 {object} string "Unauthorized"
// @Failure 404 {object} string "User settings not found"
// @Failure 500 {object} string "Server error"
// @Security BearerAuth
// @Router /profile/update [put]
func (h *Handler) UpdateProfile(c *gin.Context) {
	var req ap.UsersUpdateProfile

	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	id := claims.(jwt.MapClaims)["user_id"].(string)
	name := c.Query("full_name")
	date := c.Query("date_of_birth")
	req.Id = id
	req.FullName = name
	req.DateOfBirth = date

	_, err := h.User.UpdateProfile(context.Background(), &req)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User profile updated"})
}

// UpdateSettings godoc
// @Summary Update user settings
// @Description Update the settings of the authenticated user
// @Tags user
// @Accept json
// @Produce json
// @Param privacy_level query string false "PrivacyLevel"
// @Param notifications_enabled query string false "NotificationsEnabled"
// @Param theme query string false "Theme"
// @Param language query string false "Language"
// @Success 200 {object} string "User settings updated"
// @Failure 401 {object} string "Unauthorized"
// @Failure 404 {object} string "User settings not found"
// @Failure 500 {object} string "Server error"
// @Security BearerAuth
// @Router /settings/update [put]
func (h *Handler) UpdateSettings(c *gin.Context) {
	var req ap.UsersUpdateSettings

	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	id := claims.(jwt.MapClaims)["user_id"].(string)
	theme := c.Query("theme")
	lang := c.Query("language")
	nten := c.Query("notifications_enabled")
	prvc := c.Query("privacy_level")
	req.Id = id
	req.PrivacyLevel = prvc
	req.NotificationsEnabled = nten
	req.Theme = theme
	req.Language = lang

	_, err := h.User.SettingsUpdate(context.Background(), &req)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User settings updated"})
}

// ChangePassword godoc
// @Summary ChangePassword
// @Description ChangePassword
// @Tags user
// @Accept json
// @Produce json
// @Param current_password query string false "CurrentPassword"
// @Param new_password query string false "NewPassword"
// @Success 200 {object} string "Changed password"
// @Failure 401 {object} string "Unauthorized"
// @Failure 404 {object} string "Password incorrect"
// @Failure 500 {object} string "Server error"
// @Security BearerAuth
// @Router /change-password [put]
func (h *Handler) ChangePassword(c *gin.Context) {
	var req ap.UsersChangePassword

	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	id := claims.(jwt.MapClaims)["user_id"].(string)
	cur_pass := c.Query("current_password")
	new_pass := c.Query("new_password")

	if cur_pass == "" || cur_pass == "string" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Password incorrect"})
		return
	}
	if new_pass == "" || new_pass == "string" {
		c.JSON(http.StatusNotFound, gin.H{"error": "Password incorrect"})
		return
	}

	req.Id = id
	req.CurrentPassword = cur_pass
	req.NewPasword = new_pass

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPasword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server error"})
		return
	}

	req.NewPasword = string(hashedPassword)

	_, err = h.User.ChangePassword(context.Background(), &req)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Changed password"})
}

// ForgotPassword godoc
// @Summary Send a reset password code to the user's email
// @Description Send a reset password code to the user's email
// @Tags user
// @Accept  json
// @Produce  json
// @Param  email  body  ap.UsersForgotPassword  true  "Email data"
// @Success 200 {object} string "Reset password code sent successfully"
// @Failure 400 {object} string "Invalid input"
// @Failure 500 {object} string "Internal server error"
// @Security BearerAuth
// @Router /forgot-password [post]
func (h *Handler) ForgotPassword(c *gin.Context) {
	req := ap.UsersForgotPassword{}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	_, err := h.User.ForgotPassword(context.Background(), &req)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	fmt.Println(req.Email)

	// input,err := json.Marshal(req)
	// if err != nil {
	// 	c.JSON(500, gin.H{"error": err.Error()})
	// }

	// err = h.Producer.ProduceMessages("forgot_password",input)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "Reset password code sent successfully"})
}

// ResetPassword godoc
// @Summary Reset user password
// @Description Reset user password with the provided reset code and new password
// @Tags user
// @Accept  json
// @Produce  json
// @Param reset_token query string false "ResetToken"
// @Param new_password query string false "NewPassword"
// @Success 200 {object} string "Password reset successfully"
// @Failure 400 {object} string "Invalid input"
// @Failure 500 {object} string "Internal server error"
// @Security BearerAuth
// @Router /reset-password [post]
func (h *Handler) ResetPassword(c *gin.Context) {
	var resetCode ap.UsersResetPassword
	reset_token := c.Query("reset_token")
	new_password := c.Query("new_password")

	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	email := claims.(jwt.MapClaims)["email"].(string)

	resetCode.NewPassword = new_password
	resetCode.ResetToken = reset_token
	resetCode.Email = email

	_, err := h.User.ResetPassword(context.Background(), &resetCode)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "Password reset successfully"})
}

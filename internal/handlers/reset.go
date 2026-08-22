package handlers

import (
	"ldap-self-service/internal/models"
	"ldap-self-service/internal/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

func RequestPasswordReset(ldapService *services.LDAPService, emailService *services.EmailService, smsService *services.SMSService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.PasswordResetRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Get user from LDAP to validate username and get contact info
		user, err := ldapService.GetUser(req.Username)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		var token string
		var err2 error

		switch req.Method {
		case "email":
			if user.Email == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "No email address configured for this user"})
				return
			}
			token, err2 = emailService.SendVerificationCode(user.Email, user.Username)
		case "sms":
			if user.Phone == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "No phone number configured for this user"})
				return
			}
			token, err2 = smsService.SendVerificationCode(user.Phone, user.Username)
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid reset method. Use 'email' or 'sms'"})
			return
		}

		if err2 != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification code"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Verification code sent",
			"token":   token,
			"method":  req.Method,
		})
	}
}

func ResetPassword(ldapService *services.LDAPService, emailService *services.EmailService, smsService *services.SMSService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.PasswordResetConfirm
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Get the username BEFORE verifying the code (since VerifyCode deletes the token)
		var username string
		if smsService.HasToken(req.Token) {
			username = smsService.GetUsernameForToken(req.Token)
		} else if emailService.HasToken(req.Token) {
			username = emailService.GetUsernameForToken(req.Token)
		}
		
		if username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token or token expired"})
			return
		}

		// Now try to verify the code with both email and SMS services
		valid, _ := emailService.VerifyCode(req.Token, req.Code)
		if !valid {
			valid, _ = smsService.VerifyCode(req.Token, req.Code)
		}

		if !valid {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired verification code"})
			return
		}
		
		// Get user by username
		user, err := ldapService.GetUser(username)

		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		// Reset password using admin privileges
		if err := ldapService.ResetPassword(user.DN, req.NewPassword); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
	}
}


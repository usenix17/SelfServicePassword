package models

import "time"

type User struct {
	DN          string    `json:"dn"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	Phone       string    `json:"phone"`
	FirstName   string    `json:"firstName"`
	LastName    string    `json:"lastName"`
	SSHKeys     []SSHKey  `json:"sshKeys"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type SSHKey struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	PublicKey   string    `json:"publicKey"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"createdAt"`
}

type PasswordChangeRequest struct {
	CurrentPassword string `json:"currentPassword" binding:"required"`
	NewPassword     string `json:"newPassword" binding:"required,min=8"`
	ConfirmPassword string `json:"confirmPassword" binding:"required"`
}

type VerificationRequest struct {
	Code   string `json:"code" binding:"required"`
	Token  string `json:"token" binding:"required"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type SSHKeyRequest struct {
	Name      string `json:"name" binding:"required"`
	PublicKey string `json:"publicKey" binding:"required"`
}

type PasswordResetRequest struct {
	Username string `json:"username" binding:"required"`
	Method   string `json:"method" binding:"required"` // "email" or "sms"
}

type PasswordResetConfirm struct {
	Token       string `json:"token" binding:"required"`
	Code        string `json:"code" binding:"required"`
	NewPassword string `json:"newPassword" binding:"required,min=3"`
}
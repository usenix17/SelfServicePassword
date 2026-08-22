package services

import (
	"crypto/rand"
	"fmt"
	"ldap-self-service/internal/config"
	"math/big"
	"sync"
	"time"

	"gopkg.in/gomail.v2"
)

type EmailService struct {
	config *config.Config
	codes  map[string]*VerificationCode
	mutex  sync.RWMutex
}

type VerificationCode struct {
	Code      string
	Email     string
	Username  string
	ExpiresAt time.Time
	Token     string
}

func NewEmailService(cfg *config.Config) *EmailService {
	service := &EmailService{
		config: cfg,
		codes:  make(map[string]*VerificationCode),
	}
	
	go service.cleanupExpiredCodes()
	return service
}

func (s *EmailService) SendVerificationCode(email, username string) (string, error) {
	code, err := s.generateCode()
	if err != nil {
		return "", err
	}

	token, err := s.generateToken()
	if err != nil {
		return "", err
	}

	s.mutex.Lock()
	s.codes[token] = &VerificationCode{
		Code:      code,
		Email:     email,
		Username:  username,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Token:     token,
	}
	s.mutex.Unlock()

	if err := s.sendEmail(email, code); err != nil {
		s.mutex.Lock()
		delete(s.codes, token)
		s.mutex.Unlock()
		return "", err
	}

	return token, nil
}

func (s *EmailService) VerifyCode(token, code string) (bool, string) {
	s.mutex.RLock()
	verificationCode, exists := s.codes[token]
	s.mutex.RUnlock()

	if !exists {
		return false, ""
	}

	if time.Now().After(verificationCode.ExpiresAt) {
		s.mutex.Lock()
		delete(s.codes, token)
		s.mutex.Unlock()
		return false, ""
	}

	if verificationCode.Code != code {
		return false, ""
	}

	email := verificationCode.Email
	s.mutex.Lock()
	delete(s.codes, token)
	s.mutex.Unlock()

	return true, email
}

func (s *EmailService) sendEmail(email, code string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", fmt.Sprintf("%s <%s>", s.config.Email.FromName, s.config.Email.FromEmail))
	m.SetHeader("To", email)
	m.SetHeader("Subject", "LDAP Self-Service - Email Verification")
	
	body := fmt.Sprintf(`
		<html>
		<body>
			<h2>Email Verification</h2>
			<p>Your verification code is: <strong>%s</strong></p>
			<p>This code will expire in 10 minutes.</p>
			<p>If you didn't request this verification, please ignore this email.</p>
		</body>
		</html>
	`, code)
	
	m.SetBody("text/html", body)

	d := gomail.NewDialer(
		s.config.Email.SMTPHost,
		s.config.Email.SMTPPort,
		s.config.Email.SMTPUser,
		s.config.Email.SMTPPassword,
	)

	return d.DialAndSend(m)
}

func (s *EmailService) generateCode() (string, error) {
	const charset = "0123456789"
	code := make([]byte, 6)
	
	for i := range code {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		code[i] = charset[num.Int64()]
	}
	
	return string(code), nil
}

func (s *EmailService) generateToken() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	token := make([]byte, 32)
	
	for i := range token {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		token[i] = charset[num.Int64()]
	}
	
	return string(token), nil
}

func (s *EmailService) cleanupExpiredCodes() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mutex.Lock()
		now := time.Now()
		for token, code := range s.codes {
			if now.After(code.ExpiresAt) {
				delete(s.codes, token)
			}
		}
		s.mutex.Unlock()
	}
}

func (s *EmailService) HasToken(token string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	entry, exists := s.codes[token]
	if !exists {
		return false
	}
	
	return time.Now().Before(entry.ExpiresAt)
}

func (s *EmailService) GetUsernameForToken(token string) string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	entry, exists := s.codes[token]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return ""
	}
	
	return entry.Username
}
package services

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"ldap-self-service/internal/config"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type SMSService struct {
	config *config.Config
	codes  map[string]*SMSVerificationCode
	mutex  sync.RWMutex
}

type SMSVerificationCode struct {
	Code      string
	Phone     string
	Username  string
	ExpiresAt time.Time
	Token     string
}

func NewSMSService(cfg *config.Config) *SMSService {
	service := &SMSService{
		config: cfg,
		codes:  make(map[string]*SMSVerificationCode),
	}

	go service.cleanupExpiredCodes()
	return service
}

func (s *SMSService) SendVerificationCode(phone, username string) (string, error) {
	code, err := s.generateCode()
	if err != nil {
		return "", err
	}

	token, err := s.generateToken()
	if err != nil {
		return "", err
	}

	s.mutex.Lock()
	s.codes[token] = &SMSVerificationCode{
		Code:      code,
		Phone:     phone,
		Username:  username,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Token:     token,
	}
	s.mutex.Unlock()

	// Send asynchronously. VoIP.ms can take 10-15s to respond, and blocking
	// the HTTP response that long trips CDN/proxy timeouts (Cloudflare, etc.)
	// even though the message is delivered. The code is already stored, so
	// return the token immediately and let the SMS arrive shortly after.
	go func() {
		if err := s.sendSMS(phone, code); err != nil {
			log.Printf("async SMS send failed for user %q (%s): %v", username, phone, err)
			s.mutex.Lock()
			delete(s.codes, token)
			s.mutex.Unlock()
		}
	}()

	return token, nil
}

func (s *SMSService) VerifyCode(token, code string) (bool, string) {
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

	phone := verificationCode.Phone
	s.mutex.Lock()
	delete(s.codes, token)
	s.mutex.Unlock()

	return true, phone
}

func (s *SMSService) sendSMS(phone, code string) error {
	message := fmt.Sprintf("Your LDAP Self-Service verification code is: %s. This code expires in 10 minutes.", code)

	switch s.config.SMS.Provider {
	case "voipms":
		return s.sendVoipmsSMS(phone, message)
	case "apprise":
		return s.sendAppriseSMS(phone, message)
	case "mock":
		fmt.Printf("Mock SMS to %s: %s\n", phone, message)
		return nil
	default:
		return fmt.Errorf("unsupported SMS provider: %s", s.config.SMS.Provider)
	}
}

func (s *SMSService) sendVoipmsSMS(phone, message string) error {
	// Call the VoIP.ms REST API directly. VoIP.ms responses are slow
	// (~7-12s); the previous Apprise hop timed out at ~4s and reported a
	// failure even though the SMS was already accepted and delivered.
	creds := s.config.SMS.APISecret // Format: "api_password:api_username"
	parts := strings.SplitN(creds, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid VoIP.ms credentials: expected \"password:username\"")
	}
	apiPassword := parts[0]
	apiUsername := parts[1]

	params := url.Values{}
	params.Set("api_username", apiUsername)
	params.Set("api_password", apiPassword)
	params.Set("method", "sendSMS")
	params.Set("did", s.config.SMS.FromPhone)
	params.Set("dst", phone)
	params.Set("message", message)

	apiURL := "https://voip.ms/api/v1/rest.php?" + params.Encode()

	// Timeout comfortably above VoIP.ms latency so slow-but-successful
	// sends are not misreported as failures.
	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Get(apiURL)
	if err != nil {
		return fmt.Errorf("failed to reach VoIP.ms API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read VoIP.ms API response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("VoIP.ms API returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse VoIP.ms API response: %s", string(body))
	}

	if result.Status != "success" {
		return fmt.Errorf("VoIP.ms SMS failed: %s", result.Status)
	}

	return nil
}

func (s *SMSService) sendAppriseSMS(phone, message string) error {
	// Use Apprise API to send SMS via VoIP.ms
	apiURL := s.config.SMS.APIKey       // API URL (e.g., "https://apprise.starnix.net/notify")
	username := s.config.SMS.APISecret  // VoIP.ms credentials
	fromPhone := s.config.SMS.FromPhone // From phone number

	// Construct VoIP.ms URL: voipms://username:password@karcz.me/from_number/to_number
	voipmsURL := fmt.Sprintf("voipms://%s@karcz.me/%s/%s", username, fromPhone, phone)

	// Prepare form data
	data := url.Values{}
	data.Set("body", message)
	data.Set("urls", voipmsURL)

	// Create HTTP client with timeout and force HTTP/1.1 (Apprise server has HTTP/2 issues)
	transport := &http.Transport{
		ForceAttemptHTTP2: false, // Force HTTP/1.1
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	// Make HTTP POST request
	resp, err := client.PostForm(apiURL, data)
	if err != nil {
		return fmt.Errorf("failed to send SMS via Apprise API: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read Apprise API response: %w", err)
	}

	// Check status code
	if resp.StatusCode != 200 {
		if resp.StatusCode == 424 {
			return fmt.Errorf("VoIP.ms SMS failed (check credentials/phone format): %s", string(body))
		}
		return fmt.Errorf("Apprise API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (s *SMSService) generateCode() (string, error) {
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

func (s *SMSService) generateToken() (string, error) {
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

func (s *SMSService) cleanupExpiredCodes() {
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

func (s *SMSService) HasToken(token string) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	entry, exists := s.codes[token]
	if !exists {
		return false
	}

	return time.Now().Before(entry.ExpiresAt)
}

func (s *SMSService) GetUsernameForToken(token string) string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	entry, exists := s.codes[token]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return ""
	}

	return entry.Username
}

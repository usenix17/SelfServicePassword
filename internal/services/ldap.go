package services

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"ldap-self-service/internal/config"
	"ldap-self-service/internal/models"
	"time"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/ssh"
)

type LDAPService struct {
	config *config.Config
}

func NewLDAPService(cfg *config.Config) *LDAPService {
	return &LDAPService{config: cfg}
}

func (s *LDAPService) Connect() (*ldap.Conn, error) {
	addr := fmt.Sprintf("%s:%d", s.config.LDAP.Host, s.config.LDAP.Port)
	
	var conn *ldap.Conn
	var err error
	
	// Configure TLS settings
	tlsConfig := &tls.Config{
		InsecureSkipVerify: s.config.LDAP.InsecureSkipVerify,
		ServerName:         s.config.LDAP.Host,
	}
	
	if s.config.LDAP.UseTLS {
		if s.config.LDAP.Port == 636 {
			// Direct TLS connection (LDAPS)
			conn, err = ldap.DialTLS("tcp", addr, tlsConfig)
		} else {
			// StartTLS on standard port (usually 389)
			conn, err = ldap.Dial("tcp", addr)
			if err == nil {
				err = conn.StartTLS(tlsConfig)
			}
		}
	} else {
		conn, err = ldap.Dial("tcp", addr)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}

	if err := conn.Bind(s.config.LDAP.BindDN, s.config.LDAP.BindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	return conn, nil
}

func (s *LDAPService) Authenticate(username, password string) (*models.User, error) {
	conn, err := s.Connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		s.config.LDAP.UserBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(s.config.LDAP.UserFilter, ldap.EscapeFilter(username)),
		[]string{"dn", "uid", s.config.LDAP.EmailAttr, s.config.LDAP.PhoneAttr, "givenName", "sn", s.config.LDAP.SSHKeyAttr},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	entry := sr.Entries[0]
	userDN := entry.DN

	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	user := &models.User{
		DN:        userDN,
		Username:  entry.GetAttributeValue("uid"),
		Email:     entry.GetAttributeValue(s.config.LDAP.EmailAttr),
		Phone:     entry.GetAttributeValue(s.config.LDAP.PhoneAttr),
		FirstName: entry.GetAttributeValue("givenName"),
		LastName:  entry.GetAttributeValue("sn"),
	}

	sshKeys := entry.GetAttributeValues(s.config.LDAP.SSHKeyAttr)
	for i, key := range sshKeys {
		fingerprint := s.generateSSHKeyFingerprint(key)
		user.SSHKeys = append(user.SSHKeys, models.SSHKey{
			ID:          fmt.Sprintf("%d", i),
			Name:        fmt.Sprintf("Key %d", i+1),
			PublicKey:   key,
			Fingerprint: fingerprint,
			CreatedAt:   time.Now(),
		})
	}

	return user, nil
}

func (s *LDAPService) UpdatePassword(userDN, oldPassword, newPassword string) error {
	if err := s.validatePassword(newPassword); err != nil {
		return err
	}

	conn, err := s.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Bind(userDN, oldPassword); err != nil {
		return fmt.Errorf("current password verification failed: %w", err)
	}

	if err := conn.Bind(s.config.LDAP.BindDN, s.config.LDAP.BindPassword); err != nil {
		return fmt.Errorf("admin bind failed: %w", err)
	}

	passwordModify := ldap.NewPasswordModifyRequest(userDN, oldPassword, newPassword)
	_, err = conn.PasswordModify(passwordModify)
	if err != nil {
		return fmt.Errorf("password change failed: %w", err)
	}

	return nil
}

func (s *LDAPService) ResetPassword(userDN, newPassword string) error {
	if err := s.validatePassword(newPassword); err != nil {
		return err
	}

	conn, err := s.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Use admin privileges to reset password
	passwordModify := ldap.NewPasswordModifyRequest(userDN, "", newPassword)
	_, err = conn.PasswordModify(passwordModify)
	if err != nil {
		return fmt.Errorf("password reset failed: %w", err)
	}

	return nil
}

func (s *LDAPService) validatePassword(password string) error {
	policy := s.config.PasswordPolicy
	
	if len(password) < policy.MinLength {
		return fmt.Errorf("password must be at least %d characters long", policy.MinLength)
	}
	
	if policy.MaxLength > 0 && len(password) > policy.MaxLength {
		return fmt.Errorf("password must be no more than %d characters long", policy.MaxLength)
	}
	
	var lowerCount, upperCount, digitCount, specialCount int
	
	for _, char := range password {
		switch {
		case char >= 'a' && char <= 'z':
			lowerCount++
		case char >= 'A' && char <= 'Z':
			upperCount++
		case char >= '0' && char <= '9':
			digitCount++
		default:
			specialCount++
		}
	}
	
	if lowerCount < policy.MinLower {
		return fmt.Errorf("password must contain at least %d lowercase letter(s)", policy.MinLower)
	}
	
	if upperCount < policy.MinUpper {
		return fmt.Errorf("password must contain at least %d uppercase letter(s)", policy.MinUpper)
	}
	
	if digitCount < policy.MinDigit {
		return fmt.Errorf("password must contain at least %d digit(s)", policy.MinDigit)
	}
	
	if specialCount < policy.MinSpecial {
		return fmt.Errorf("password must contain at least %d special character(s)", policy.MinSpecial)
	}
	
	return nil
}

func (s *LDAPService) GetUser(username string) (*models.User, error) {
	conn, err := s.Connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		s.config.LDAP.UserBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(s.config.LDAP.UserFilter, ldap.EscapeFilter(username)),
		[]string{"dn", "uid", s.config.LDAP.EmailAttr, s.config.LDAP.PhoneAttr, "givenName", "sn", s.config.LDAP.SSHKeyAttr},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	entry := sr.Entries[0]
	user := &models.User{
		DN:        entry.DN,
		Username:  entry.GetAttributeValue("uid"),
		Email:     entry.GetAttributeValue(s.config.LDAP.EmailAttr),
		Phone:     entry.GetAttributeValue(s.config.LDAP.PhoneAttr),
		FirstName: entry.GetAttributeValue("givenName"),
		LastName:  entry.GetAttributeValue("sn"),
	}

	sshKeys := entry.GetAttributeValues(s.config.LDAP.SSHKeyAttr)
	for i, key := range sshKeys {
		fingerprint := s.generateSSHKeyFingerprint(key)
		user.SSHKeys = append(user.SSHKeys, models.SSHKey{
			ID:          fmt.Sprintf("%d", i),
			Name:        fmt.Sprintf("Key %d", i+1),
			PublicKey:   key,
			Fingerprint: fingerprint,
		})
	}

	return user, nil
}

func (s *LDAPService) AddSSHKey(userDN, sshKey string) error {
	if err := s.validateSSHKey(sshKey); err != nil {
		return err
	}

	conn, err := s.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	modifyRequest := ldap.NewModifyRequest(userDN, nil)
	modifyRequest.Add(s.config.LDAP.SSHKeyAttr, []string{sshKey})

	if err := conn.Modify(modifyRequest); err != nil {
		return fmt.Errorf("failed to add SSH key: %w", err)
	}

	return nil
}

func (s *LDAPService) RemoveSSHKey(userDN, sshKey string) error {
	conn, err := s.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	modifyRequest := ldap.NewModifyRequest(userDN, nil)
	modifyRequest.Delete(s.config.LDAP.SSHKeyAttr, []string{sshKey})

	if err := conn.Modify(modifyRequest); err != nil {
		return fmt.Errorf("failed to remove SSH key: %w", err)
	}

	return nil
}

func (s *LDAPService) validateSSHKey(key string) error {
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return fmt.Errorf("invalid SSH key format: %w", err)
	}
	return nil
}

func (s *LDAPService) generateSSHKeyFingerprint(key string) string {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		hash := md5.Sum([]byte(key))
		return fmt.Sprintf("MD5:%x", hash)
	}

	hash := sha256.Sum256(pubKey.Marshal())
	return fmt.Sprintf("SHA256:%s", base64.StdEncoding.EncodeToString(hash[:]))
}
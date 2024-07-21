package postgres

import (
	ap "auth/genproto"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	t "auth/api/token"
	"auth/verification"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UsersRepo struct {
	db  *sql.DB
	rdb *redis.Client
}

func NewUsersRepo(db *sql.DB, rdb *redis.Client) *UsersRepo {
	return &UsersRepo{db: db, rdb: rdb}
}

func (u *UsersRepo) Register(req *ap.UsersRegister) (*ap.Void, error) {
	id := uuid.New().String()
	void := ap.Void{}

	query := `
	INSERT INTO users (
		id,
		username,
		email,
		password_hash,
		full_name,
		date_of_birth,
		role
	) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := u.db.Exec(query, id, req.Username, req.Email, req.Password, req.FullName, req.DateOfBirth, req.Role)

	if err != nil {
		log.Println("Error while registering user: ", err)
		return nil, err
	}

	log.Println("Successfully registered user")

	return &void, nil
}
func (u *UsersRepo) Login(req *ap.UsersLogin) (*ap.Tokens, error) {
	var id string
	var username string
	var email string
	var password string

	query := `
	SELECT 
		id,
		username,
		email,
		password_hash
	FROM 
		users
	WHERE
		username = $1
	`

	row := u.db.QueryRow(query, req.Username)

	err := row.Scan(
		&id,
		&username,
		&email,
		&password,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}

	if err != nil {
		log.Println("Error while login user: ", err)
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(password), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid username or password")
	}

	token := t.GenerateJWTToken(id, email, username)
	tokens := ap.Tokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return &tokens, nil
}
func (u *UsersRepo) Profile(req *ap.UsersProfileReq) (*ap.UsersProfile, error) {
	user := ap.UsersProfile{}

	query := `
	SELECT 
		id,
		username,
		email,
		full_name,
		date_of_birth
	FROM 	
		users
	WHERE
		username = $1
	`
	row := u.db.QueryRow(query, req.Username)

	err := row.Scan(
		&user.Id,
		&user.Username,
		&user.Email,
		&user.FullName,
		&user.DateOfBirth,
	)

	if err != nil {
		log.Println("Error while getting user profile: ", err)
		return nil, err
	}

	fmt.Println("Succesfully got profile")

	return &user, nil
}
func (u *UsersRepo) UpdateProfile(req *ap.UsersUpdateProfile) (*ap.Void, error) {
	void := ap.Void{}

	query := `
	UPDATE
		users
	SET 
	`

	var conditions []string
	var args []interface{}

	if req.FullName != "" && req.FullName != "string" {
		conditions = append(conditions, " full_name = $"+strconv.Itoa(len(args)+1))
		args = append(args, req.FullName)
	}
	if req.DateOfBirth != "" && req.DateOfBirth != "string" {
		conditions = append(conditions, " date_of_birth = $"+strconv.Itoa(len(args)+1))
		args = append(args, req.DateOfBirth)
	}

	if len(conditions) == 0 {
		return nil, errors.New("nothing to update")
	}

	conditions = append(conditions, " updated_at = now()")
	query += strings.Join(conditions, ", ")
	query += " WHERE id = $" + strconv.Itoa(len(args)+1) + " AND deleted_at = 0 "

	args = append(args, req.Id)

	_, err := u.db.Exec(query, args...)

	if err != nil {
		log.Println("Error while updating user profile: ", err)
		return nil, err
	}

	log.Println("Successfully updated user profile")

	return &void, nil
}
func (u *UsersRepo) ForgotPassword(req *ap.UsersForgotPassword) (*ap.Void, error) {
	code, err := verification.GenerateRandomCode(6)
	if err != nil {
		return nil, errors.New("failed to generate code for verification" + err.Error())
	}

	u.rdb.Set(context.Background(), req.Email, code, time.Minute*5)

	from := "axadjonovsardorbeck@gmail.com"
	password := "ypuw yybh sqjr boww"
	err = verification.SendVerificationCode(verification.Params{
		From:     from,
		Password: password,
		To:       req.Email,
		Message:  fmt.Sprintf("Hi %s, your verification:%s", req.Email, code),
		Code:     code,
	})

	if err != nil {
		return nil, errors.New("failed to send verification email" + err.Error())
	}
	return nil, nil
}

func (u *UsersRepo) ResetPassword(req *ap.UsersResetPassword) (*ap.Void, error) {
	em, err := u.rdb.Get(context.Background(), req.Email).Result()
	log.Println(req.ResetToken, err)
	if err != nil {
		return nil, errors.New("invalid code or code expired")
	}
	log.Println(em)

	if req.NewPassword == "" || req.NewPassword == "string" {
		return nil, errors.New("incorrect password")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New("failed to reset password")
	}
	req.NewPassword = string(hashedPassword)

	query := `update users set password_hash = $1 where email = $2 and deleted_at = 0`
	_, err = u.db.Exec(query, req.NewPassword, em)
	log.Println(req.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to reset password: %v", err)
	}
	return nil, nil
}
func (u *UsersRepo) ChangePassword(req *ap.UsersChangePassword) (*ap.Void, error) {
	var cur_pass string

	query_current := `SELECT password_hash FROM users WHERE id = $1 AND deleted_at = 0`

	row := u.db.QueryRow(query_current, req.Id)

	err := row.Scan(&cur_pass)

	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(cur_pass), []byte(req.CurrentPassword)); err != nil {
		return nil, errors.New("invalid password")
	}

	query_update := `UPDATE users SET password_hash = $1 WHERE id = $2 AND deleted_at = 0`

	_, err = u.db.Exec(query_update, req.NewPasword, req.Id)

	if err != nil {
		return nil, err
	}

	return nil, nil
}
func (u *UsersRepo) Settings(req *ap.UsersProfileReq) (*ap.UsersSettings, error) {
	setting := ap.UsersSettings{}

	query := `
	SELECT 
		privacy_level,
		notifications_enabled,
		language,
		theme
	FROM 	
		users
	WHERE
		username = $1
	`
	row := u.db.QueryRow(query, req.Username)

	err := row.Scan(
		&setting.PrivacyLevel,
		&setting.NotificationsEnabled,
		&setting.Language,
		&setting.Theme,
	)

	if err != nil {
		log.Println("Error while getting setting: ", err)
		return nil, err
	}

	fmt.Println("Succesfully got setting")

	return &setting, nil
}
func (u *UsersRepo) SettingsUpdate(req *ap.UsersUpdateSettings) (*ap.Void, error) {
	void := ap.Void{}

	query := `
	UPDATE
		users
	SET 
	`

	var conditions []string
	var args []interface{}

	if req.PrivacyLevel != "" && req.PrivacyLevel != "string" {
		conditions = append(conditions, " privacy_level = $"+strconv.Itoa(len(args)+1))
		args = append(args, req.PrivacyLevel)
	}
	if req.Language != "" && req.Language != "string" {
		conditions = append(conditions, " language = $"+strconv.Itoa(len(args)+1))
		args = append(args, req.Language)
	}
	if req.Theme != "" && req.Theme != "string" {
		conditions = append(conditions, " theme = $"+strconv.Itoa(len(args)+1))
		args = append(args, req.Theme)
	}
	if req.NotificationsEnabled != "" && req.NotificationsEnabled != "string" {
		conditions = append(conditions, " notifications_enabled = $"+strconv.Itoa(len(args)+1))
		args = append(args, req.NotificationsEnabled)
	}

	if len(conditions) == 0 {
		return nil, errors.New("nothing to update")
	}

	conditions = append(conditions, " updated_at = now()")
	query += strings.Join(conditions, ", ")
	query += " WHERE id = $" + strconv.Itoa(len(args)+1) + " AND deleted_at = 0 "

	args = append(args, req.Id)

	_, err := u.db.Exec(query, args...)

	if err != nil {
		log.Println("Error while updating user setting: ", err)
		return nil, err
	}

	log.Println("Successfully updated user setting")

	return &void, nil
}

package storage

import (
	ap "auth/genproto"
)

type UserI interface {
	Register(*ap.UsersRegister) (*ap.Void, error)
	Login(*ap.UsersLogin) (*ap.Tokens, error)
	Profile(*ap.UsersProfileReq) (*ap.UsersProfile, error)
	UpdateProfile(*ap.UsersUpdateProfile) (*ap.Void, error)
	ForgotPassword(*ap.UsersForgotPassword) (*ap.Void, error)
	ResetPassword(*ap.UsersResetPassword) (*ap.Void, error)
	ChangePassword(*ap.UsersChangePassword) (*ap.Void, error)
	Settings(*ap.UsersProfileReq) (*ap.UsersSettings, error)
	SettingsUpdate(*ap.UsersUpdateSettings) (*ap.Void, error)
}

package service

import (
	ap "auth/genproto"
	st "auth/storage/postgres"
	"context"
)

type UsersService struct {
	storage st.Storage
	ap.UnimplementedUserServiceServer
}

func NewUsersService(storage *st.Storage) *UsersService {
	return &UsersService{storage: *storage}
}

func (u *UsersService) Register(ctx context.Context, req *ap.UsersRegister) (*ap.Void, error) {
	return u.storage.UserS.Register(req)
}
func (u *UsersService) Login(ctx context.Context, req *ap.UsersLogin) (*ap.Tokens, error) {
	return u.storage.UserS.Login(req)
}
func (u *UsersService) Profile(ctx context.Context, req *ap.UsersProfileReq) (*ap.UsersProfile, error) {
	return u.storage.UserS.Profile(req)
}
func (u *UsersService) UpdateProfile(ctx context.Context, req *ap.UsersUpdateProfile) (*ap.Void, error) {
	return u.storage.UserS.UpdateProfile(req)
}
func (u *UsersService) ForgotPassword(ctx context.Context, req *ap.UsersForgotPassword) (*ap.Void, error) {
	return u.storage.UserS.ForgotPassword(req)
}
func (u *UsersService) ResetPassword(ctx context.Context, req *ap.UsersResetPassword) (*ap.Void, error) {
	return u.storage.UserS.ResetPassword(req)
}
func (u *UsersService) ChangePassword(ctx context.Context, req *ap.UsersChangePassword) (*ap.Void, error) {
	return u.storage.UserS.ChangePassword(req)
}
func (u *UsersService) Settings(ctx context.Context, req *ap.UsersProfileReq) (*ap.UsersSettings, error) {
	return u.storage.UserS.Settings(req)
}
func (u *UsersService) SettingsUpdate(ctx context.Context, req *ap.UsersUpdateSettings) (*ap.Void, error) {
	return u.storage.UserS.SettingsUpdate(req)
}

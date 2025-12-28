package use_cases

type LogoutUserUseCasePort interface {
	Logout(refreshToken string) error
}

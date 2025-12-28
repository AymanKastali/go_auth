package use_cases

type LogoutUserUseCasePort interface {
	Execute(refreshToken string) error
}

package services

type PasswordService interface {
	Hash(raw string) (string, error)
	Compare(raw string, hashed string) bool
}

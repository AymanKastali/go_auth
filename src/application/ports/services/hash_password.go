package services

type HashPasswordPort interface {
	Hash(raw string) (string, error)
	Compare(raw string, hashed string) bool
}

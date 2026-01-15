package ports

type ISeederConfig interface {
	AdminEmail() string
	AdminPassword() string
}

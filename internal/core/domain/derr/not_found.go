package derr

import "fmt"

type ErrRoleNotFound struct{ RoleName string }

func NewErrRoleNotFound(roleName string) *ErrRoleNotFound {
	return &ErrRoleNotFound{RoleName: roleName}
}
func (e *ErrRoleNotFound) Error() string {
	return fmt.Sprintf("role definition for '%s' could not be found", e.RoleName)
}

func (e *ErrRoleNotFound) Code() ErrorCode {
	return CodeNotFound
}

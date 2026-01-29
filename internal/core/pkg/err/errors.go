package err

type Code string

const (
	CodeValidation   Code = "VALIDATION_FAILED"
	CodeConflict     Code = "CONFLICT"
	CodeNotFound     Code = "NOT_FOUND"
	CodeBusinessRule Code = "BUSINESS_RULE_VIOLATION"
	CodeUnauthorized Code = "UNAUTHORIZED"
	CodeForbidden    Code = "FORBIDDEN"
	CodeInternal     Code = "INTERNAL"
)

type Error struct {
	code    Code
	message string
}

func (e *Error) Error() string   { return e.message }
func (e *Error) Code() Code      { return e.code }
func (e *Error) Message() string { return e.message }

func New(code Code, msg string) error { return &Error{code: code, message: msg} }

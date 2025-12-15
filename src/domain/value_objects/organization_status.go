package valueobjects

type OrganizationStatus string

const (
	OrgActive    OrganizationStatus = "ACTIVE"
	OrgSuspended OrganizationStatus = "SUSPENDED"
	OrgDeleted   OrganizationStatus = "DELETED"
)

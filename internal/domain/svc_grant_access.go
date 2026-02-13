package domain

import "time"

type IGrantAccess interface {
	Grant(
		user *User,
		sid SessionID,
		roles []*Role,
		now time.Time,
	) (AccessToken, time.Time, error)
}

type grantAccess struct {
	permResolver IResolvePermissions
	accessSvc    IAccessService
	accessPolicy IAccessPolicy
}

func NewGrantAccess(
	permResolver IResolvePermissions,
	accessSvc IAccessService,
	accessPolicy IAccessPolicy,
) IGrantAccess {
	return &grantAccess{
		permResolver: permResolver,
		accessSvc:    accessSvc,
		accessPolicy: accessPolicy,
	}
}

func (g *grantAccess) Grant(
	user *User,
	sid SessionID,
	roles []*Role,
	now time.Time,
) (AccessToken, time.Time, error) {
	issuedAt := now
	notBefore := now

	ttl := g.accessPolicy.GetAccessLifetime()
	expiresAt := issuedAt.Add(ttl)

	permissions := g.permResolver.Resolve(roles)

	return g.accessSvc.Issue(
		user.ID(),
		user.Email(),
		sid,
		user.Roles(),
		permissions,
		issuedAt,
		expiresAt,
		notBefore,
	)
}

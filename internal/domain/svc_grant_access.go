package domain

import (
	"context"
	"time"
)

type IGrantAccess interface {
	Grant(
		ctx context.Context,
		user *User,
		sid SessionID,
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
	ctx context.Context,
	user *User,
	sid SessionID,
	now time.Time,
) (AccessToken, time.Time, error) {
	issuedAt := now
	notBefore := now

	ttl := g.accessPolicy.GetAccessLifetime()
	expiresAt := issuedAt.Add(ttl)

	permissions, err := g.permResolver.Resolve(ctx, user.Roles())
	if err != nil {
		return ZeroAccessToken, time.Time{}, err
	}

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

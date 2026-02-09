package postgres

import (
	"context"

	"go_auth/internal/application"
	"go_auth/internal/domain"

	"gorm.io/gorm"
)

// PersistenceFactory encapsulates the database connection and provides
// repository and infrastructure constructors. This keeps *gorm.DB hidden
// from the composition root.
type PersistenceFactory struct {
	db *gorm.DB
}

// NewPersistenceFactory connects to Postgres, runs migrations, and returns
// a ready-to-use factory.
func NewPersistenceFactory(databaseURL string) (*PersistenceFactory, error) {
	db, err := NewPostgresConnection(databaseURL)
	if err != nil {
		return nil, err
	}

	if err := Migrate(db); err != nil {
		return nil, err
	}

	return &PersistenceFactory{db: db}, nil
}

func (f *PersistenceFactory) NewUserRepository() domain.IUserRepository {
	return NewPostgresUserRepository(f.db)
}

func (f *PersistenceFactory) NewSessionRepository() domain.ISessionRepository {
	return NewPostgresSessionRepository(f.db)
}

func (f *PersistenceFactory) NewRoleRepository() domain.IRoleRepository {
	return NewPostgresRoleRepository(f.db)
}

func (f *PersistenceFactory) NewRecoveryTokenRepository() domain.IRecoveryTokenRepository {
	return NewPostgresRecoveryTokenRepository(f.db)
}

func (f *PersistenceFactory) NewActivationTokenRepository() domain.IActivationTokenRepository {
	return NewPostgresActivationTokenRepository(f.db)
}

func (f *PersistenceFactory) NewUserQueryAdapter() application.IUserQueryPort {
	return NewPostgresUserQueryAdapter(f.db)
}

func (f *PersistenceFactory) NewTransactionManager() application.ITransactionManager {
	return NewTransactionManager(f.db)
}

func (f *PersistenceFactory) Ping(ctx context.Context) error {
	sqlDB, err := f.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

func (f *PersistenceFactory) Close() error {
	return Close(f.db)
}

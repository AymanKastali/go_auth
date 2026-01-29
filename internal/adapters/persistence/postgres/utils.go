package postgres

import (
	"context"

	"gorm.io/gorm"
)

type ctxKey string

const txKey ctxKey = "tx_key"

type transactionManager struct {
	db *gorm.DB
}

func NewTransactionManager(db *gorm.DB) *transactionManager {
	return &transactionManager{db: db}
}

func (tm *transactionManager) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return tm.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Wrap the transaction in the context using the internal key
		return fn(context.WithValue(ctx, txKey, tx))
	})
}

func getDB(db *gorm.DB, ctx context.Context) *gorm.DB {
	if tx, ok := ctx.Value(txKey).(*gorm.DB); ok {
		return tx.WithContext(ctx)
	}
	return db.WithContext(ctx)
}

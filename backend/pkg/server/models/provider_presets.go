package models

import (
	"time"

	"github.com/jinzhu/gorm"
)

// ProviderPreset stores a reusable API configuration preset that can be
// selected when configuring individual swarm agents.
type ProviderPreset struct {
	ID          uint64    `form:"id" json:"id" validate:"min=0,numeric" gorm:"type:BIGINT;NOT NULL;PRIMARY_KEY;AUTO_INCREMENT"`
	UserID      uint64    `form:"user_id" json:"user_id" validate:"min=0,numeric" gorm:"type:BIGINT;NOT NULL"`
	Name        string    `form:"name" json:"name" validate:"required" gorm:"type:VARCHAR(128);NOT NULL"`
	APIProvider string    `form:"api_provider" json:"api_provider" validate:"required" gorm:"type:VARCHAR(64);NOT NULL"`
	APIKey      string    `form:"api_key" json:"api_key" validate:"required" gorm:"type:TEXT;NOT NULL"`
	APIEndpoint string    `form:"api_endpoint" json:"api_endpoint" validate:"required" gorm:"type:TEXT;NOT NULL"`
	Model       string    `form:"model" json:"model" validate:"required" gorm:"type:VARCHAR(128);NOT NULL"`
	CreatedAt   time.Time `form:"created_at,omitempty" json:"created_at,omitempty" validate:"omitempty" gorm:"type:TIMESTAMPTZ;default:CURRENT_TIMESTAMP"`
	UpdatedAt   time.Time `form:"updated_at,omitempty" json:"updated_at,omitempty" validate:"omitempty" gorm:"type:TIMESTAMPTZ;default:CURRENT_TIMESTAMP"`
}

// TableName returns the table name string to guarantee use of correct table
func (p *ProviderPreset) TableName() string {
	return "provider_presets"
}

// Valid is function to control input/output data
func (p ProviderPreset) Valid() error {
	return validate.Struct(p)
}

// Validate is function to use callback to control input/output data
func (p ProviderPreset) Validate(db *gorm.DB) {
	if err := p.Valid(); err != nil {
		db.AddError(err)
	}
}

// ProviderPresetRequest is the request body for creating or updating a preset
type ProviderPresetRequest struct {
	Name        string `form:"name" json:"name" validate:"required"`
	APIProvider string `form:"api_provider" json:"api_provider" validate:"required"`
	APIKey      string `form:"api_key" json:"api_key" validate:"required"`
	APIEndpoint string `form:"api_endpoint" json:"api_endpoint" validate:"required"`
	Model       string `form:"model" json:"model" validate:"required"`
}

// Valid is function to control input/output data
func (r ProviderPresetRequest) Valid() error {
	return validate.Struct(r)
}

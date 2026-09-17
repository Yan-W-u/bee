package models

import (
	"time"

	"github.com/jinzhu/gorm"
)

// SwarmAgentConfig stores a single agent's configuration
type SwarmAgentConfig struct {
	ID          uint64    `form:"id" json:"id" validate:"min=0,numeric" gorm:"type:BIGINT;NOT NULL;PRIMARY_KEY;AUTO_INCREMENT"`
	UserID      uint64    `form:"user_id" json:"user_id" validate:"min=0,numeric" gorm:"type:BIGINT;NOT NULL"`
	AgentID     string    `form:"agent_id" json:"agent_id" validate:"required" gorm:"type:VARCHAR(64);NOT NULL"`
	APIProvider string    `form:"api_provider" json:"api_provider" validate:"required" gorm:"type:VARCHAR(64);NOT NULL"`
	APIKey      string    `form:"api_key" json:"api_key" validate:"required" gorm:"type:TEXT;NOT NULL"`
	APIEndpoint string    `form:"api_endpoint" json:"api_endpoint" validate:"required" gorm:"type:TEXT;NOT NULL"`
	Model       string    `form:"model" json:"model" validate:"required" gorm:"type:VARCHAR(128);NOT NULL"`
	Status      string    `form:"status" json:"status" validate:"required" gorm:"type:VARCHAR(32);NOT NULL;default:'unconfigured'"`
	CreatedAt   time.Time `form:"created_at,omitempty" json:"created_at,omitempty" validate:"omitempty" gorm:"type:TIMESTAMPTZ;default:CURRENT_TIMESTAMP"`
	UpdatedAt   time.Time `form:"updated_at,omitempty" json:"updated_at,omitempty" validate:"omitempty" gorm:"type:TIMESTAMPTZ;default:CURRENT_TIMESTAMP"`
}

// TableName returns the table name string to guarantee use of correct table
func (s *SwarmAgentConfig) TableName() string {
	return "swarm_agent_configs"
}

// Valid is function to control input/output data
func (s SwarmAgentConfig) Valid() error {
	return validate.Struct(s)
}

// Validate is function to use callback to control input/output data
func (s SwarmAgentConfig) Validate(db *gorm.DB) {
	if err := s.Valid(); err != nil {
		db.AddError(err)
	}
}

// SwarmConfigRequest is the request body for saving all swarm configs
type SwarmConfigRequest struct {
	Agents []SwarmAgentConfig `form:"agents" json:"agents" validate:"required"`
}

// Valid is function to control input/output data
func (r SwarmConfigRequest) Valid() error {
	return validate.Struct(r)
}

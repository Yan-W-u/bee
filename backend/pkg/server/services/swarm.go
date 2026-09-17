package services

import (
	"net/http"

	"pentagi/pkg/server/logger"
	"pentagi/pkg/server/models"
	"pentagi/pkg/server/response"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
)

type SwarmService struct {
	orm *gorm.DB
}

func NewSwarmService(orm *gorm.DB) *SwarmService {
	return &SwarmService{orm: orm}
}

// GetSwarmConfigs returns all swarm agent configs for the current user
func (s *SwarmService) GetSwarmConfigs(c *gin.Context) {
	uid := c.GetUint64("uid")
	var configs []models.SwarmAgentConfig

	if err := s.orm.Where("user_id = ?", uid).Find(&configs).Error; err != nil {
		logger.FromContext(c).WithError(err).Errorf("error finding swarm configs")
		response.Error(c, response.ErrInternal, err)
		return
	}

	response.Success(c, http.StatusOK, configs)
}

// SaveSwarmConfigs saves or updates all swarm agent configs for the current user
func (s *SwarmService) SaveSwarmConfigs(c *gin.Context) {
	uid := c.GetUint64("uid")
	var req models.SwarmConfigRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.FromContext(c).WithError(err).Errorf("error binding JSON")
		response.Error(c, response.ErrSwarmInvalidRequest, err)
		return
	}

	if err := req.Valid(); err != nil {
		logger.FromContext(c).WithError(err).Errorf("error validating swarm config request")
		response.Error(c, response.ErrSwarmInvalidRequest, err)
		return
	}

	// Delete existing configs for this user
	if err := s.orm.Where("user_id = ?", uid).Delete(&models.SwarmAgentConfig{}).Error; err != nil {
		logger.FromContext(c).WithError(err).Errorf("error deleting existing swarm configs")
		response.Error(c, response.ErrInternal, err)
		return
	}

	// Insert new configs
	for _, cfg := range req.Agents {
		cfg.UserID = uid
		if err := s.orm.Create(&cfg).Error; err != nil {
			logger.FromContext(c).WithError(err).Errorf("error creating swarm config")
			response.Error(c, response.ErrInternal, err)
			return
		}
	}

	response.Success(c, http.StatusOK, req.Agents)
}

package services

import (
	"net/http"
	"strconv"

	"pentagi/pkg/server/logger"
	"pentagi/pkg/server/models"
	"pentagi/pkg/server/response"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
)

type ProviderPresetService struct {
	orm *gorm.DB
}

func NewProviderPresetService(orm *gorm.DB) *ProviderPresetService {
	return &ProviderPresetService{orm: orm}
}

// ListProviderPresets returns all provider presets for the current user
func (s *ProviderPresetService) ListProviderPresets(c *gin.Context) {
	uid := c.GetUint64("uid")
	var presets []models.ProviderPreset

	if err := s.orm.Where("user_id = ?", uid).Order("id DESC").Find(&presets).Error; err != nil {
		logger.FromContext(c).WithError(err).Errorf("error finding provider presets")
		response.Error(c, response.ErrInternal, err)
		return
	}

	response.Success(c, http.StatusOK, presets)
}

// CreateProviderPreset creates a new provider preset for the current user
func (s *ProviderPresetService) CreateProviderPreset(c *gin.Context) {
	uid := c.GetUint64("uid")
	var req models.ProviderPresetRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.FromContext(c).WithError(err).Errorf("error binding JSON")
		response.Error(c, response.ErrProviderPresetInvalidRequest, err)
		return
	}

	if err := req.Valid(); err != nil {
		logger.FromContext(c).WithError(err).Errorf("error validating provider preset request")
		response.Error(c, response.ErrProviderPresetInvalidRequest, err)
		return
	}

	preset := models.ProviderPreset{
		UserID:      uid,
		Name:        req.Name,
		APIProvider: req.APIProvider,
		APIKey:      req.APIKey,
		APIEndpoint: req.APIEndpoint,
		Model:       req.Model,
	}

	if err := s.orm.Create(&preset).Error; err != nil {
		logger.FromContext(c).WithError(err).Errorf("error creating provider preset")
		response.Error(c, response.ErrInternal, err)
		return
	}

	response.Success(c, http.StatusCreated, preset)
}

// UpdateProviderPreset updates an existing provider preset for the current user
func (s *ProviderPresetService) UpdateProviderPreset(c *gin.Context) {
	uid := c.GetUint64("uid")
	id, err := strconv.ParseUint(c.Param("presetID"), 10, 64)
	if err != nil {
		response.Error(c, response.ErrProviderPresetInvalidRequest, err)
		return
	}

	var req models.ProviderPresetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.FromContext(c).WithError(err).Errorf("error binding JSON")
		response.Error(c, response.ErrProviderPresetInvalidRequest, err)
		return
	}

	if err := req.Valid(); err != nil {
		logger.FromContext(c).WithError(err).Errorf("error validating provider preset request")
		response.Error(c, response.ErrProviderPresetInvalidRequest, err)
		return
	}

	var preset models.ProviderPreset
	if err := s.orm.Where("id = ? AND user_id = ?", id, uid).First(&preset).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			response.Error(c, response.ErrProviderPresetNotFound, err)
			return
		}
		logger.FromContext(c).WithError(err).Errorf("error finding provider preset")
		response.Error(c, response.ErrInternal, err)
		return
	}

	preset.Name = req.Name
	preset.APIProvider = req.APIProvider
	preset.APIKey = req.APIKey
	preset.APIEndpoint = req.APIEndpoint
	preset.Model = req.Model

	if err := s.orm.Save(&preset).Error; err != nil {
		logger.FromContext(c).WithError(err).Errorf("error updating provider preset")
		response.Error(c, response.ErrInternal, err)
		return
	}

	response.Success(c, http.StatusOK, preset)
}

// DeleteProviderPreset deletes a provider preset for the current user
func (s *ProviderPresetService) DeleteProviderPreset(c *gin.Context) {
	uid := c.GetUint64("uid")
	id, err := strconv.ParseUint(c.Param("presetID"), 10, 64)
	if err != nil {
		response.Error(c, response.ErrProviderPresetInvalidRequest, err)
		return
	}

	if err := s.orm.Where("id = ? AND user_id = ?", id, uid).Delete(&models.ProviderPreset{}).Error; err != nil {
		logger.FromContext(c).WithError(err).Errorf("error deleting provider preset")
		response.Error(c, response.ErrInternal, err)
		return
	}

	response.Success(c, http.StatusOK, gin.H{"id": id})
}

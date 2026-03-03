package appconfig

import (
	"os"

	"gopkg.in/yaml.v3"
)

type MuteConfig struct {
	Vulnerabilities []VulnerabilityMute `yaml:"vulnerabilities,omitempty"` // optional
}

type VulnerabilityMute struct {
	ID        string `yaml:"id"`                  // required
	Namespace string `yaml:"namespace"`           // required
	ImageName string `yaml:"imageName,omitempty"` // optional
}

func loadMuteConfig() (*MuteConfig, error) {
	if _, err := os.Stat("mute.yaml"); os.IsNotExist(err) {
		return &MuteConfig{}, nil //nolint:exhaustruct
	}

	contents, err := os.ReadFile("mute.yaml")
	if err != nil {
		return nil, err
	}

	var muteConfig MuteConfig
	if err := yaml.Unmarshal(contents, &muteConfig); err != nil {
		return nil, err
	}

	return &muteConfig, nil
}

func (muteConfig *MuteConfig) IsMutedVulnerability(namespace, vulnerabilityID, imageName string) bool {
	for _, mute := range muteConfig.Vulnerabilities {
		if mute.ID == vulnerabilityID && mute.Namespace == namespace {
			if mute.ImageName == "" || mute.ImageName == imageName {
				return true
			}
		}
	}

	return false
}

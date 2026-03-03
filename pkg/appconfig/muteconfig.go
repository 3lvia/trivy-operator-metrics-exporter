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
	Reason    string `yaml:"reason"`              // required
	Namespace string `yaml:"namespace,omitempty"` // optional
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

func (muteConfig *MuteConfig) IsMutedVulnerability(vulnID, namespace, imageName string) bool {
	if vulnID == "" {
		return false
	}

	// If only ID is specified, mute all vulnerabilities with the same ID.
	//
	// If ID and Namespace are specified:
	// - mute all vulnerabilities with the same ID in the same Namespace.
	//
	// If ID and ImageName are specified:
	// - mute all vulnerabilities with the same ID in the same ImageName.
	//
	// If ID, Namespace and ImageName are specified:
	// - mute all vulnerabilities with the same ID in the same Namespace and the same ImageName.
	//
	for _, mute := range muteConfig.Vulnerabilities {
		if mute.ID == vulnID {
			if (mute.Namespace == "" || mute.Namespace == namespace) &&
				(mute.ImageName == "" || mute.ImageName == imageName) {
				return true
			}
		}
	}

	return false
}

package outbound

import (
	"fmt"
	"os"

	"go_auth/internal/application"

	"gopkg.in/yaml.v3"
)

type yamlRoleSeedLoader struct {
	path string
}

func NewYAMLRoleSeedLoader(path string) application.IRoleSeedLoader {
	return &yamlRoleSeedLoader{path: path}
}

type roleSeedFile struct {
	Roles []roleSeedEntry `yaml:"roles"`
}

type roleSeedEntry struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Permissions []string `yaml:"permissions"`
}

func (l *yamlRoleSeedLoader) Load() ([]application.RoleSeedDefinition, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return nil, fmt.Errorf("role seed loader: failed to read %s: %w", l.path, err)
	}

	var file roleSeedFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("role seed loader: failed to parse %s: %w", l.path, err)
	}

	defs := make([]application.RoleSeedDefinition, len(file.Roles))
	for i, r := range file.Roles {
		defs[i] = application.RoleSeedDefinition{
			Name:        r.Name,
			Description: r.Description,
			Permissions: r.Permissions,
		}
	}

	return defs, nil
}

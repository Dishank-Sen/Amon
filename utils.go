package utils

import (
	"os"

	"github.com/Dishank-Sen/Amon/internal/paths"
	"github.com/Dishank-Sen/Amon/types"
	"gopkg.in/yaml.v3"
)


func Load(path string) (*types.Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var cfg types.Config

    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }

    return &cfg, nil
}

func GetEventThreshold() int{
    cfg, err := Load(paths.ConfigFile())
    if err != nil{
        // send default buffer threshold
        return 300
    }
    return cfg.EventsThreshold
}
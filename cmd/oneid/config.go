package main

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Environment string
	AppName     string
	Database    struct {
		Name     string
		Host     string
		Port     string
		User     string
		Password string
	}
	AuthServer struct {
		Host string
		Port string
	}
	AppServer struct {
		Host string
		Port string
	}
	SigningKey string
}

func readConfig() (Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/ondeid/")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		return Config{}, fmt.Errorf("can't read config file: %w", err)
	}

	viper.SetEnvPrefix("OID")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("can't unmarshal config: %w", err)
	}

	return cfg, nil
}

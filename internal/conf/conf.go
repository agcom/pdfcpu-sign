package conf

import "github.com/spf13/viper"

func init() {
	viper.SetEnvPrefix("SIGN_SERVER")
	viper.AutomaticEnv()
}

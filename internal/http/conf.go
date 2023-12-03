package http

import (
	_ "github.com/agcom/pdfcpu-sign/internal/conf"
	"github.com/spf13/viper"
)

const httpPortConfKey = "http_port"

var port = 0

func init() {
	viper.SetDefault(httpPortConfKey, 4648)

	// TODO: should manually check the existence of conf keys and their types (GetType would not panic if a value of incorrect type is given).
	port = viper.GetInt(httpPortConfKey)
}

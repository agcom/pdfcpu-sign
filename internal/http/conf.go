package http

import (
	_ "github.com/agcom/pdfcpu-sign/internal/conf"
	"github.com/spf13/viper"
)

const httpPortConfKey = "http_port"

var port = 0

func init() {
	viper.SetDefault(httpPortConfKey, 4648)

	port = viper.GetInt(httpPortConfKey)
}

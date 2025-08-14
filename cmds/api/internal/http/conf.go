package http

import (
	"fmt"
	"os"

	_ "github.com/agcom/pdfcpu-sign/cmds/api/internal/conf"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
)

const confKeyPrefix = "http_"

const httpPortConfKey = confKeyPrefix + "port"

func init() {
	viper.SetDefault(httpPortConfKey, 4648)
}

func getHttpPortConf() (int, error) {
	portAny := viper.Get(httpPortConfKey)
	if portAny == nil {
		return 0, fmt.Errorf("port conf not found (wraps: %w)", os.ErrNotExist) // TODO (minor improvement): create and use our own ErrNotExists.
	}

	if port, err := cast.ToIntE(portAny); err != nil {
		return 0, fmt.Errorf("bad port conf: %v; %w", portAny, err)
	} else {
		return port, nil
	}
}

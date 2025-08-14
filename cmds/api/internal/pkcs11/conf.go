package pkcs11

import (
	"encoding/hex"
	"fmt"
	"os"

	_ "github.com/agcom/pdfcpu-sign/cmds/api/internal/conf"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
)

const confKeyPrefix = "pkcs11_"

const libPathConfKey = confKeyPrefix + "lib_path"

const (
	tokenSlotConfKey   = confKeyPrefix + "token_slot"
	tokenSerialConfKey = confKeyPrefix + "token_serial"
	tokenLabelConfKey  = confKeyPrefix + "token_label"
)

const tokenPinConfKey = confKeyPrefix + "token_pin"

const (
	kertIdHexConfKey = confKeyPrefix + "kert_id_hex"
	kertLabelConfKey = confKeyPrefix + "kert_label"
)

func init() {
	viper.SetDefault(libPathConfKey, "/usr/local/lib/softhsm/libsofthsm2.so")
	// No default values for other keys, because they should not to be non-deterministic.
}

func getLibPathConf() (string, error) {
	libPathAny := viper.Get(libPathConfKey)
	if libPathAny == nil {
		return "", fmt.Errorf("lib path conf not provided")
	}

	libPath, err := cast.ToStringE(libPathAny)
	if err != nil {
		return "", fmt.Errorf("bad lib path conf given: %v; %w", libPathAny, err)
	}

	return libPath, nil
}

func getTokenIdsConf() (slot int, serial string, label string, err error) {
	slot = -1 // Zero value.

	slotAny := viper.Get(tokenSlotConfKey)
	serialAny := viper.Get(tokenSerialConfKey)
	labelAny := viper.Get(tokenLabelConfKey)

	if slotAny == nil && serialAny == nil && labelAny == nil {
		err = fmt.Errorf("no token identifier is provided")
		return
	}

	resetReturns := func() {
		slot = -1
		serial = ""
		label = ""
	}

	if slotAny != nil {
		slot, err = cast.ToIntE(slotAny)
		if err != nil {
			resetReturns()
			err = fmt.Errorf("bad token slot conf given: %v", slotAny)
			return
		}
	}

	if serialAny != nil {
		serial, err = cast.ToStringE(serialAny)
		if err != nil {
			resetReturns()
			err = fmt.Errorf("bad token serial conf given: %v", serialAny)
		}
	}

	if labelAny != nil {
		label, err = cast.ToStringE(labelAny)
		if err != nil {
			resetReturns()
			err = fmt.Errorf("bad token label given: %v", labelAny)
		}
	}

	return
}

func getTokenPinConf() (string, error) {
	pinAny := viper.Get(tokenPinConfKey)

	if pinAny == nil {
		return "", fmt.Errorf("no token pin conf provided (wraps: %w)", os.ErrNotExist) // TODO (minor improvement): create and use our own not exists error.
	}

	pin, err := cast.ToStringE(pinAny)
	if err != nil {
		return "", fmt.Errorf("bad token pin conf given: %v; %w", pinAny, err)
	}

	return pin, nil
}

func getKertIdsConf() (id []byte, label string, err error) {
	idHexAny := viper.Get(kertIdHexConfKey)
	labelAny := viper.Get(kertLabelConfKey)

	if idHexAny == nil && labelAny == nil {
		err = fmt.Errorf("no kert identifier provided (wraps: %w)", os.ErrNotExist) // TODO (minor improvement): create and use our own not exists error.
		return
	}

	resetReturns := func() {
		id = nil
		label = ""
	}

	if idHexAny != nil {
		var idHex string
		idHex, err = cast.ToStringE(idHexAny)
		if err != nil {
			resetReturns()
			err = fmt.Errorf("bad kert id hex conf given: %v", idHexAny)
			return
		}

		id, err = hex.DecodeString(idHex)
		if err != nil {
			resetReturns()
			err = fmt.Errorf("bad non-hex kert id hex conf given: %q", idHex)
			return
		}
	}

	if labelAny != nil {
		label, err = cast.ToStringE(labelAny)
		if err != nil {
			resetReturns()
			err = fmt.Errorf("bad kert label conf given: %v", labelAny)
			return
		}
	}

	return
}

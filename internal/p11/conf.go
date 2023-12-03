package p11

import (
	_ "github.com/agcom/pdfcpu-sign/internal/conf"
	"github.com/spf13/viper"
	"log"
	"log/slog"
)

const pkcs11LibPathConfKey = "pkcs11_lib_path"

var Pkcs11LibPath string

func init() {
	viper.SetDefault(pkcs11LibPathConfKey, "/usr/local/lib/softhsm/libsofthsm2.so")

	Pkcs11LibPath = viper.GetString(pkcs11LibPathConfKey)
	if Pkcs11LibPath == "" {
		log.Panicln("PKCS#11 library path is not provided.")
	}
}

const (
	tokenSlotConfKey   = "token_slot"
	tokenSerialConfKey = "token_serial"
	tokenLabelConfKey  = "token_label"
)

var TokenSlot int
var TokenSerial string
var TokenLabel string

func init() {
	// No default values for TokenSlotConf & TokenSerialConf & TokenLabelConf, because they should not to be non-deterministic.

	TokenSlot = viper.GetInt(tokenSlotConfKey)
	TokenSerial = viper.GetString(tokenSerialConfKey)
	TokenLabel = viper.GetString(tokenLabelConfKey)

	// TODO: make sure that logging the slot number or token serial or token label is not considered a security concern.
	if viper.IsSet(tokenSlotConfKey) && viper.GetString(tokenSlotConfKey) != "" { // Token slot can be 0; thus can not use TokenSlot != 0 as the condition.
		slog.Info("Using the given slot number to identify the token.", "slot", TokenSlot)
		if TokenSerial != "" {
			slog.Warn("Ignoring the given token serial.", "serial", TokenSerial)
			TokenSerial = ""
		}
		if TokenLabel != "" {
			slog.Warn("Ignoring the given token label.", "label", TokenLabel)
			TokenLabel = ""
		}
	} else if TokenSerial != "" {
		slog.Info("Using the given token serial to identify the token.", "serial", TokenSerial)
		if TokenLabel != "" {
			slog.Warn("Ignoring the given token label.", "label", TokenLabel)
			TokenLabel = ""
		}
	} else if TokenLabel != "" {
		slog.Info("Using the given token label to identify the token.", "label", TokenLabel)
	} else {
		log.Panicln("No way to identify the token is provided.")
	}

	// TODO: fetch x508.VerifyOptions.Roots and x509.VerifyOptions.Intermediates as configurations to be used for certificate verification.
}

const tokenPinConfKey = "token_pin"

var TokenPin string

func init() {
	TokenPin = viper.GetString(tokenPinConfKey)
	if TokenPin == "" {
		slog.Warn("No PIN provided for the token.")
	}
}

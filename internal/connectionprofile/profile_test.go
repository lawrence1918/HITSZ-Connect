package connectionprofile

import (
	"testing"

	"github.com/mythologyli/zju-connect/configs"
)

func TestHITSZUsesSystemRoutingByDefault(t *testing.T) {
	config := configs.Config{
		Profile:       "hitsz",
		ServerAddress: "rvpn.zju.edu.cn",
		LoginDomain:   "Radius",
		SocksBind:     ":1080",
		HTTPBind:      ":1081",
	}

	if err := Apply(&config); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if config.AutoDetectInterface {
		t.Fatal("HITSZ profile unexpectedly enabled underlay auto-detection")
	}
	if config.BindInterface != "" {
		t.Fatalf("BindInterface = %q, want system routing", config.BindInterface)
	}
}

func TestHITSZPreservesExplicitAutoDetection(t *testing.T) {
	config := configs.Config{
		Profile:             "hitsz",
		ServerAddress:       "trust.hitsz.edu.cn",
		AutoDetectInterface: true,
	}

	if err := Apply(&config); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !config.AutoDetectInterface {
		t.Fatal("explicit underlay auto-detection was not preserved")
	}
}

func TestHITSZPreservesExplicitUnderlay(t *testing.T) {
	config := configs.Config{
		Profile:       "hitsz",
		ServerAddress: "trust.hitsz.edu.cn",
		BindInterface: "en7",
	}

	if err := Apply(&config); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if config.AutoDetectInterface {
		t.Fatal("explicit bind interface unexpectedly enabled auto-detection")
	}
	if config.BindInterface != "en7" {
		t.Fatalf("BindInterface = %q, want en7", config.BindInterface)
	}
}

func TestHITSZSecureConfigMigratesRegressedAutoDetection(t *testing.T) {
	config := configs.Config{
		Profile:             "hitsz",
		ServerAddress:       "trust.hitsz.edu.cn",
		BindInterface:       "en-test",
		AutoDetectInterface: true,
	}

	if err := ApplySecureConfig(&config); err != nil {
		t.Fatalf("ApplySecureConfig() error = %v", err)
	}
	if config.AutoDetectInterface {
		t.Fatal("legacy HITSZ secure config still enables underlay auto-detection")
	}
	if config.BindInterface != "en-test" {
		t.Fatalf("BindInterface = %q, want en-test", config.BindInterface)
	}
}

func TestNonHITSZSecureConfigPreservesAutoDetection(t *testing.T) {
	config := configs.Config{
		Protocol:            "easyconnect",
		ServerAddress:       "vpn.example.edu",
		AutoDetectInterface: true,
	}

	if err := ApplySecureConfig(&config); err != nil {
		t.Fatalf("ApplySecureConfig() error = %v", err)
	}
	if !config.AutoDetectInterface {
		t.Fatal("non-HITSZ secure config lost explicit underlay auto-detection")
	}
}

func TestValidateFileSourcePathsRejectsConsumedFlagName(t *testing.T) {
	config := configs.Config{ClientDataFile: "-shadowrocket"}
	if err := ValidateFileSourcePaths(config); err == nil {
		t.Fatal("missing client-data path that consumed the next flag was accepted")
	}
	config.ClientDataFile = "./-shadowrocket"
	if err := ValidateFileSourcePaths(config); err != nil {
		t.Fatalf("explicit relative filename beginning with dash was rejected: %v", err)
	}
}

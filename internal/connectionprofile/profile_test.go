package connectionprofile

import (
	"testing"

	"github.com/mythologyli/zju-connect/configs"
)

func TestHITSZUsesPhysicalUnderlayByDefault(t *testing.T) {
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
	if !config.AutoDetectInterface {
		t.Fatal("HITSZ profile did not enable physical underlay auto-detection")
	}
	if config.BindInterface != "" {
		t.Fatalf("BindInterface = %q, want empty auto-detected interface", config.BindInterface)
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

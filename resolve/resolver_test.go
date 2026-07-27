package resolve

import (
	"testing"

	"github.com/mythologyli/zju-connect/client"
)

func TestFindDomainResourceNormalizesWildcardAndChoosesLongestSuffix(t *testing.T) {
	root := client.DomainResource{AppID: "root"}
	portal := client.DomainResource{AppID: "portal"}
	resources := map[string]client.DomainResource{
		"*.hitsz.edu.cn":       root,
		"portal.hitsz.edu.cn.": portal,
	}

	got, domain, ok := findDomainResource("Login.Portal.HITSZ.EDU.CN.", resources)
	if !ok || domain != "portal.hitsz.edu.cn" || got.AppID != portal.AppID {
		t.Fatalf("findDomainResource() = (%+v, %q, %t), want portal resource", got, domain, ok)
	}

	got, domain, ok = findDomainResource("net.hitsz.edu.cn", resources)
	if !ok || domain != "hitsz.edu.cn" || got.AppID != root.AppID {
		t.Fatalf("wildcard resource not matched: (%+v, %q, %t)", got, domain, ok)
	}

	if _, _, ok := findDomainResource("not-hitsz.edu.cn", resources); ok {
		t.Fatal("suffix match ignored the DNS label boundary")
	}
}

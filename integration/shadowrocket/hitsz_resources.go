package shadowrocket

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"

	"github.com/mythologyli/zju-connect/client"
)

// HITSZResourceCIDRs converts the port-aware resources issued by aTrust into
// exact IPv4 CIDRs for Shadowrocket. Only the confirmed HITSZ campus address
// space (10.248.0.0/16 through 10.250.0.0/16) is emitted. Shadowrocket cannot
// express the aTrust port/protocol ACL in an IP-CIDR rule, so the loopback
// proxy continues to enforce that ACL and fails closed for other ports.
func HITSZResourceCIDRs(resources []client.IPResource) []string {
	cidrs := make([]string, 0, len(resources))
	for _, resource := range resources {
		start, ok := ipv4AsUint32(resource.IPMin)
		if !ok {
			continue
		}
		end, ok := ipv4AsUint32(resource.IPMax)
		if !ok || end < start {
			continue
		}

		if start < hitszCampusStart {
			start = hitszCampusStart
		}
		if end > hitszCampusEnd {
			end = hitszCampusEnd
		}
		if end < start {
			continue
		}
		cidrs = append(cidrs, ipv4RangeCIDRs(start, end)...)
	}
	return normalizedHITSZCampusIPv4CIDRs(cidrs)
}

func ipv4AsUint32(ip net.IP) (uint32, bool) {
	ip = ip.To4()
	if ip == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip), true
}

// ipv4RangeCIDRs returns the minimum collection of CIDRs that exactly covers
// the closed range [start, end]. It uses uint64 internally so a /0-sized range
// cannot overflow while advancing to the next block.
func ipv4RangeCIDRs(start, end uint32) []string {
	from, to := uint64(start), uint64(end)
	cidrs := make([]string, 0, 1)
	for from <= to {
		block := from & -from
		if block == 0 {
			block = 1 << 32
		}
		remaining := to - from + 1
		for block > remaining {
			block >>= 1
		}
		prefixBits := 32 - (bits.Len64(block) - 1)
		ip := net.IPv4(byte(from>>24), byte(from>>16), byte(from>>8), byte(from))
		cidrs = append(cidrs, fmt.Sprintf("%s/%d", ip.String(), prefixBits))
		from += block
	}
	return cidrs
}

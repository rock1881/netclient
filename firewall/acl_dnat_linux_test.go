package firewall

import (
	"net"
	"strings"
	"testing"

	"github.com/gravitl/netmaker/models"
)

func cidr(t *testing.T, s string) net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return *n
}

func TestDNATACLConstraints(t *testing.T) {
	local := []net.IP{net.ParseIP("100.90.0.2"), net.ParseIP("fd90::2")}
	base := func() models.AclRule {
		return models.AclRule{ID: "policy", Allowed: true, AllowedProtocol: models.TCP,
			IPList: []net.IPNet{cidr(t, "100.90.0.1/32")}, Dst: []net.IPNet{cidr(t, "100.90.0.2/32")}, AllowedPorts: []string{"8090"}}
	}
	cases := []struct {
		name string
		edit func(*models.AclRule)
		want int
	}{
		{"published port", func(r *models.AclRule) {}, 1},
		{"routed destination is not local", func(r *models.AclRule) { r.Dst = []net.IPNet{cidr(t, "172.18.0.0/16")} }, 0},
		{"disabled", func(r *models.AclRule) { r.Allowed = false }, 0},
		{"unknown protocol", func(r *models.AclRule) { r.AllowedProtocol = "sctp" }, 0},
		{"all protocols and ports", func(r *models.AclRule) { r.AllowedProtocol = models.ALL; r.AllowedPorts = nil }, 1},
		{"port with no transport", func(r *models.AclRule) { r.AllowedProtocol = models.ALL }, 0},
		{"invalid ports fail closed", func(r *models.AclRule) { r.AllowedPorts = []string{"", "0", "65536", "90-80", "1-2-3", "abc"} }, 0},
		{"ranges deduplicate", func(r *models.AclRule) { r.AllowedPorts = []string{"8090-8091", "8090:8091"} }, 1},
		{"no source", func(r *models.AclRule) { r.IPList = nil }, 0},
		{"ipv6 separate", func(r *models.AclRule) {
			r.IP6List = []net.IPNet{cidr(t, "fd90::1/128")}
			r.Dst6 = []net.IPNet{cidr(t, "fd90::2/128")}
		}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			tc.edit(&r)
			got := dnatACLMatches(r, local)
			if len(got) != tc.want {
				t.Fatalf("got %v, want %d", got, tc.want)
			}
		})
	}
	got := dnatACLMatches(base(), local)[0]
	spec := strings.Join(got.ruleSpec("policy"), " ")
	for _, match := range []string{"-i netmaker", "-s 100.90.0.1/32", "--ctstate DNAT", "--ctdir ORIGINAL", "--ctorigdst 100.90.0.2", "--ctorigdstport 8090", "NETMAKER-DNAT:policy", "-j RETURN"} {
		if !strings.Contains(spec, match) {
			t.Fatalf("missing %q in %s", match, spec)
		}
	}
	if strings.Contains(spec, "--dport") {
		t.Fatal("must match original, not translated port")
	}
}

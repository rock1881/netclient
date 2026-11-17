package firewall

// Local change: enforce device ACLs against the original destination of DNAT
// traffic (e.g. Docker published ports). Only a local mesh address qualifies.
import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/models"
	"golang.org/x/sys/unix"
)

type dnatACLMatch struct {
	src         net.IPNet
	dst         net.IP
	proto       models.Protocol
	port        string
	first, last uint16
}

func dnatACLMatches(rule models.AclRule, local []net.IP) (matches []dnatACLMatch) {
	if !rule.Allowed {
		return
	}
	switch rule.AllowedProtocol {
	case "", models.ALL, models.TCP, models.UDP, models.ICMP:
	default:
		return
	}
	ports := rule.AllowedPorts
	if len(ports) == 0 {
		ports = []string{""}
	} else if rule.AllowedProtocol != models.TCP && rule.AllowedProtocol != models.UDP {
		return
	}
	seen := map[string]bool{}
	for _, address := range local {
		v4 := address.To4() != nil
		if address.To16() == nil {
			continue
		}
		sources, destinations := rule.IPList, rule.Dst
		if !v4 {
			sources, destinations = rule.IP6List, rule.Dst6
		}
		allowed := len(destinations) == 0
		for _, dst := range destinations {
			if dst.Contains(address) {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		for _, src := range sources {
			if src.IP.To16() == nil || (src.IP.To4() != nil) != v4 {
				continue
			}
			ones, bits := src.Mask.Size()
			if bits != 32 && bits != 128 {
				continue
			}
			if v4 {
				src.IP = src.IP.To4()
				src.Mask = net.CIDRMask(ones, 32)
			} else {
				src.IP = src.IP.To16()
			}
			src.IP = src.IP.Mask(src.Mask)
			for _, port := range ports {
				m := dnatACLMatch{src: src, dst: address, proto: rule.AllowedProtocol}
				if len(rule.AllowedPorts) > 0 {
					p := strings.Split(strings.TrimSpace(strings.ReplaceAll(port, ":", "-")), "-")
					if len(p) < 1 || len(p) > 2 {
						continue
					}
					lo, err := strconv.Atoi(p[0])
					if err != nil || lo < 1 || lo > 65535 {
						continue
					}
					hi := lo
					if len(p) == 2 {
						hi, err = strconv.Atoi(p[1])
						if err != nil || hi < lo || hi > 65535 {
							continue
						}
					}
					m.first, m.last = uint16(lo), uint16(hi)
					m.port = strconv.Itoa(lo)
					if lo != hi {
						m.port += ":" + strconv.Itoa(hi)
					}
				}
				key := fmt.Sprintf("%s|%s|%s|%s", src.String(), address.String(), m.proto, m.port)
				if seen[key] {
					continue
				}
				seen[key] = true
				matches = append(matches, m)
			}
		}
	}
	return
}

func (m dnatACLMatch) ruleSpec(id string) []string {
	rule := []string{"-i", ncutils.GetInterfaceName(), "-s", m.src.String()}
	if m.proto != "" && m.proto != models.ALL {
		proto := m.proto.String()
		if m.proto == models.ICMP && m.dst.To4() == nil {
			proto = "ipv6-icmp"
		}
		rule = append(rule, "-p", proto)
	}
	rule = append(rule, "-m", "conntrack", "--ctstate", "DNAT", "--ctdir", "ORIGINAL", "--ctorigdst", m.dst.String())
	if m.port != "" {
		rule = append(rule, "--ctorigdstport", m.port)
	}
	// Return to FORWARD so Docker/user firewall rules still apply.
	return append(rule, "-m", "comment", "--comment", "NETMAKER-DNAT:"+id, "-j", "RETURN")
}

// Called with the manager mutex held. Rules share the ACL's normal lifecycle.
func (i *iptablesManager) addDNATAclRules(rule models.AclRule) (rules []ruleInfo) {
	for _, m := range dnatACLMatches(rule, config.LocalNodeAddresses()) {
		client := i.ipv4Client
		v4 := m.dst.To4() != nil
		if !v4 {
			client = i.ipv6Client
		}
		spec := m.ruleSpec(rule.ID)
		if err := client.Insert(defaultIpTable, aclFwdRulesChain, 1, spec...); err != nil {
			logger.Log(0, "failed to add DNAT ACL", rule.ID, err.Error())
			continue
		}
		rules = append(rules, ruleInfo{isIpv4: v4, table: defaultIpTable, chain: aclFwdRulesChain, rule: spec})
	}
	return
}

func (n *nftablesManager) addDNATAclRules(rule models.AclRule) (rules []ruleInfo) {
	for _, m := range dnatACLMatches(rule, config.LocalNodeAddresses()) {
		v4 := m.dst.To4() != nil
		family := byte(unix.NFPROTO_IPV6)
		dst := m.dst.To16()
		if v4 {
			family = unix.NFPROTO_IPV4
			dst = m.dst.To4()
		}
		e := []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nullTerminatedString(ncutils.GetInterfaceName())},
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
			&expr.Ct{Key: expr.CtKeySTATUS, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(1 << 5 /* IPS_DST_NAT from linux/netfilter/nf_conntrack_common.h */), Xor: make([]byte, 4)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
			&expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
		}
		e = append(e, n.GetIpExpr(m.src, net.IPNet{})...)
		e = append(e, &expr.Ct{Key: expr.CtKeyDST, Direction: 0, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dst})
		if m.proto != "" && m.proto != models.ALL {
			proto := byte(unix.IPPROTO_TCP)
			if m.proto == models.UDP {
				proto = unix.IPPROTO_UDP
			}
			if m.proto == models.ICMP {
				proto = unix.IPPROTO_ICMP
				if !v4 {
					proto = unix.IPPROTO_ICMPV6
				}
			}
			e = append(e, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}})
		}
		if m.port != "" {
			lo, hi := make([]byte, 2), make([]byte, 2)
			binary.BigEndian.PutUint16(lo, m.first)
			binary.BigEndian.PutUint16(hi, m.last)
			e = append(e, &expr.Ct{Key: expr.CtKeyPROTODST, Direction: 0, Register: 1})
			if m.first == m.last {
				e = append(e, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: lo})
			} else {
				e = append(e, &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: lo, ToData: hi})
			}
		}
		e = append(e, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictReturn})
		// nftables limits rule userdata to 256 bytes. Hash the full match and
		// policy ID so IPv6 addresses/ranges fit and overlapping ACLs stay distinct.
		digest := sha256.Sum256([]byte(genRuleKey(m.ruleSpec(rule.ID)...)))
		spec := []string{fmt.Sprintf("NETMAKER-DNAT:%x", digest)}
		nf := &nftables.Rule{Table: filterTable, Chain: &nftables.Chain{Name: aclFwdRulesChain}, Exprs: e, UserData: []byte(genRuleKey(spec...))}
		n.conn.InsertRule(nf)
		if err := n.conn.Flush(); err != nil {
			logger.Log(0, "failed to add DNAT ACL", rule.ID, err.Error())
			continue
		}
		rules = append(rules, ruleInfo{isIpv4: v4, table: defaultIpTable, chain: aclFwdRulesChain, rule: spec, nfRule: nf})
	}
	return
}

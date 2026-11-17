// This isolated integration probe uses the unmodified Netclient firewall package.
// Run only in disposable containers: firewall.Init resets Netmaker's own chains.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/firewall"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
)

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func main() {
	if os.Args[1] == "connect" {
		protocol, addr := os.Args[2], os.Args[3]
		c, err := net.DialTimeout(protocol, addr, 2*time.Second)
		check(err)
		defer c.Close()
		check(c.SetDeadline(time.Now().Add(2 * time.Second)))
		_, err = c.Write([]byte("direction-ok"))
		check(err)
		b := make([]byte, 12)
		_, err = io.ReadFull(c, b)
		check(err)
		if string(b) != "direction-ok" {
			check(fmt.Errorf("wrong response: %q", b))
		}
		fmt.Println("PASS", protocol, addr, "request and reply")
		return
	}
	if os.Args[1] != "serve" {
		panic("serve fixture.json [iptables|nftables] | connect tcp|udp address")
	}
	config.Netclient().FirewallInUse = schema.FIREWALL_IPTABLES
	if len(os.Args) > 3 && os.Args[3] == "nftables" {
		config.Netclient().FirewallInUse = schema.FIREWALL_NFTABLES
	}
	b, err := os.ReadFile(os.Args[2])
	check(err)
	var update models.FwUpdate
	check(json.Unmarshal(b, &update))
	cleanup, err := firewall.Init()
	check(err)
	defer cleanup()
	firewall.ProcessAclRules("direction-test", &update)
	l, err := net.Listen("tcp", ":18080")
	check(err)
	u, err := net.ListenPacket("udp", ":18081")
	check(err)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := u.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = u.WriteTo(buf[:n], addr)
		}
	}()
	fmt.Println("READY")
	for {
		c, err := l.Accept()
		check(err)
		go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
	}
}

# Directional ACL integration probe

This fork starts from upstream v1.7.0 on branch `feat/acl-direction`.
The probe exercises the production firewall package, including the DNAT ACL fix.

The probe imports Netclient's actual `firewall` package. It accepts a server-generated
`models.FwUpdate`, installs it, and listens for TCP/UDP echo requests. Run it only in
disposable containers: `firewall.Init()` rebuilds Netmaker's own firewall chains.

`test.py` uses a dedicated internal Docker network, removes its two containers and
network on exit, and verifies request/reply from A to B while rejecting new flows
from B to A. It tests both iptables and nftables with v1.7.0 and v1.6.0 code.

Prerequisites:

- Export `device-to-device-{0,1}.json` from the sibling Netmaker
  `TestCEDirectionPolicyAndPeerUpdates` using `ACL_DIRECTION_FIXTURE_DIR`.
- Build this probe as `.local-artifacts/acl-direction-probe` with Go 1.26,
  `GOOS=linux GOARCH=amd64 CGO_ENABLED=0`.
- Copy the same probe into a v1.6.0 source checkout and build it as
  `.local-artifacts/acl-direction-probe-v1.6.0` in this repository.
- Build `local/netclient-acl-probe:v1.7.0` using this directory's Dockerfile with
  this repository as build context, then run `python3 local/acl-direction-probe/test.py`.

2026-11-17 result: all four version/backend combinations passed TCP, UDP and ICMP
forward traffic and replies, and rejected reverse new traffic.

## Docker published-port regression

`dnat_test.py` creates two isolated networks and four disposable containers. It
translates mesh ports 8090/8091 to the same backend TCP port, plus a UDP mapping.
Both iptables and nftables must pass these checks:

- An authorized source can reach the permitted original mesh port and receive replies.
- A denied source, a different original port/protocol, and direct container-IP access
  remain blocked.
- A later host firewall rule can still reject the packet.
- Policy port changes, ranges, overlapping policies, and deletion affect new flows.
- The all-protocols/all-ports policy still works without admitting other sources.

Run `python3 local/acl-direction-probe/dnat_test.py` after rebuilding the probe image.
`ACL_DIRECTION_LOCAL_ADDRESS` supplies the router's own mesh IP in the test;
`SIGHUP` reloads the fixture through `firewall.ProcessAclRules`.

## DNAT behavior

Docker translates the destination before the filter/FORWARD hook, so ordinary
INPUT ACLs for a mesh address do not protect or authorize a published container
port. `firewall/acl_dnat_linux.go` derives extra FORWARD rules from the existing
per-device ACL. They require ingress on the mesh interface, the allowed source,
DNAT in the original direction, and the original destination matching a local
mesh address. Protocol and port restrictions apply to the original published
port, not the container's translated port. Rules return to the host FORWARD chain
so downstream Docker/user firewall decisions remain effective.

Rules use the normal ACL update/delete lifecycle. Existing established sessions
retain the upstream conntrack behavior; deleting an ACL restricts new connections
rather than forcibly terminating existing sessions. Routed destinations still
require their existing egress policies. This change does not authorize an entire
Docker subnet. The code handles IPv4/IPv6 families; the live packet regression
currently covers IPv4.

The nftables dependency is pinned to official commit
`8a8ad2be810324e22fbfc7db3259d3d76e5d811d`, which fixes the one-byte conntrack
DIRECTION attribute encoding/decoding. v0.3.0 cannot read these rules back reliably,
which otherwise leaves obsolete DNAT permissions behind on policy updates.

Build Linux binaries with Go 1.26 and `CGO_ENABLED=0`; set `GOARCH=arm64` for ARM
servers. Version and executable name remain `v1.7.0` / `netclient`.

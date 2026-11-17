# Directional ACL integration probe

This directory adds a test harness only. Netclient production code is unchanged.
The parent repository is the upstream v1.7.0 tag on branch `feat/acl-direction`.

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

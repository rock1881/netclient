FROM alpine:3.24.4
RUN apk add --no-cache iproute2 iptables nftables iputils
COPY .local-artifacts/acl-direction-probe /usr/local/bin/acl-direction-probe
ENTRYPOINT ["/bin/sh", "-c", "ip link set eth0 down && ip link set eth0 name netmaker && ip link set netmaker up && exec acl-direction-probe serve /fixture.json ${FIREWALL_BACKEND:-iptables}"]

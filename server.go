package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/armon/go-socks5"
	"github.com/gobwas/glob"
	"golang.org/x/net/context"
)

type ServerRuleSet struct {
	Whitelist []FilterSpec
}

func (p *ServerRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	for _, v := range p.Whitelist {
		if v.Port != 0 {
			if v.Port != req.DestAddr.Port {
				continue
			}
		}

		if v.IPNet.IP != nil {
			if v.IPNet.Contains(req.DestAddr.IP) {
				fmt.Printf("pass: dest ip %v matches whitelisted subnet %v\n", req.DestAddr.IP, v.IPNet)
				return ctx, true
			}
		}

		if v.HostnameGlob != nil {
			if v.HostnameGlob.Match(req.DestAddr.FQDN) {
				fmt.Printf("pass: dest FQDN %s matches whitelisted hostname glob %v\n", req.DestAddr.FQDN, v.HostnameGlob)
				return ctx, true
			}

		}

	}
	fmt.Printf("reject: FDQN: %s IP: %s PORT: %d\n", req.DestAddr.FQDN, req.DestAddr.IP, req.DestAddr.Port)
	return ctx, false
}

type FilterSpec struct {
	HostnameGlob glob.Glob
	IPNet        net.IPNet
	Port         int
}

func ParseFilterList(s string) []FilterSpec {
	filterSpecList := []FilterSpec{}
	specParts := strings.Split(s, " ")
	for _, v := range specParts {
		destParts := strings.SplitN(v, ":", 2)
		host := destParts[0]
		if len(host) > 0 {
			filterSpec := FilterSpec{}

			if len(destParts) == 2 {
				if i, err := strconv.Atoi(destParts[1]); err == nil {
					filterSpec.Port = i
				}

			}
			// parse as CIDR (e.g. 1.2.3/24) first
			_, ipNet, err := net.ParseCIDR(host)
			if err == nil {
				filterSpec.IPNet = *ipNet
			} else {
				// then try to parse as IP address
				ip := net.ParseIP(host)
				if ip != nil {
					filterSpec.IPNet.IP = ip
					filterSpec.IPNet.Mask = net.IPMask{0xff, 0xff, 0xff, 0xff}
				} else {
					// if it's not an IP then assume it's FQDN
					filterSpec.HostnameGlob = glob.MustCompile(host, '.')
				}

			}

			filterSpecList = append(filterSpecList, filterSpec)
		}

	}
	return filterSpecList
}

func main() {
	whitelist := ParseFilterList(os.Getenv("PROXY_DEST_WHITELIST"))
	creds := socks5.StaticCredentials{
		os.Getenv("PROXY_USER"): os.Getenv("PROXY_PASSWORD"),
	}
	cator := socks5.UserPassAuthenticator{Credentials: creds}
	// Create a SOCKS5 server
	conf := &socks5.Config{
		AuthMethods: []socks5.Authenticator{cator},
		Logger:      log.New(os.Stdout, "", log.LstdFlags),
	}

	if len(whitelist) > 0 {
		conf.Rules = &ServerRuleSet{whitelist}
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", "0.0.0.0:1080"); err != nil {
		panic(err)
	}
}

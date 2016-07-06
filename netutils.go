package auth

import (
	"net"
	"strings"
)

//Parse IP addr in CIDR format (addr/bits)
func SplitNetAddrV4(addr string) (ipnet *net.IPNet, err error) {
	if addr == "*" || addr == "" {
		addr = "0.0.0.0/32"
	}
	if !strings.Contains(addr, "/") {
		addr += "/32"
	}
	_, ipnet, err = net.ParseCIDR(addr)
	return
}

//Convert string network list to list in IPnet format
func ParseNetworkList(acllist string) ([]net.IPNet, error) {
	var ipnets []net.IPNet
	acllist = strings.Replace(acllist, ",", " ", -1)
	acllist = strings.Replace(acllist, ";", " ", -1)
	acl_fields := strings.Fields(acllist)
	for _, field := range acl_fields {
		ipnet, err := SplitNetAddrV4(field)
		if err != nil {
			return nil, err
		}
		ipnets = append(ipnets, *ipnet)
	}
	for _, value := range ipnets {
		log.Debugf("\n%s", value.String())
	}
	return ipnets, nil
}

//Check if IP addr in string in network range
/*func IsNetworkContainsAddr4(ip_s string, ipnet *IPNet) bool {
	ip := ParseIP(ip_s)
	return ipnet.Contains(ip)
}*/

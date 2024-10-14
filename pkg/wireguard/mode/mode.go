package mode

import (
	"io"
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireGuardManager interface {
	GetPeer(name string) *PeerConfig
	UpdatePeer(nodeName, pubKeyHex string, nodeIPv4, nodeIPv6 net.IP) error
	DeletePeer(nodeName string) error
	Init(ipcache *ipcache.IPCache) error
	RestoreFinished() error
	OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP,
		oldID *ipcache.Identity, newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata)
}

// WireguardClient is an interface to mock wgctrl.Client
type WireguardClient interface {
	io.Closer
	Devices() ([]*wgtypes.Device, error)
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}

// PeerConfig represents the kernel state of each WireGuard peer.
// In order to be able to add and remove individual IPs from the
// `AllowedIPs` list, we store a `PeerConfig` for each known WireGuard peer.
// When a peer is first discovered via node manager, we obtain the remote
// peers `AllowedIPs` by querying Cilium's user-space copy of the IPCache
// in the agent. In addition, we also subscribe to IPCache updates in the
// WireGuard agent and update the `AllowedIPs` list of known peers
// accordingly.
type PeerConfig struct {
	PubKey             wgtypes.Key
	Endpoint           *net.UDPAddr
	NodeIPv4, NodeIPv6 net.IP
	AllowedIPs         []net.IPNet
}

// RemoveAllowedIP removes ip from the list of allowedIPs and returns true
// if the list of allowedIPs changed
func (p *PeerConfig) RemoveAllowedIP(ip net.IPNet) (updated bool) {
	filtered := p.AllowedIPs[:0]
	for _, allowedIP := range p.AllowedIPs {
		if cidr.Equal(&allowedIP, &ip) {
			updated = true
		} else {
			filtered = append(filtered, allowedIP)
		}
	}

	p.AllowedIPs = filtered
	return updated
}

// InsertAllowedIP inserts ip into the list of allowedIPs and returns true
// if the list of allowedIPs changed
func (p *PeerConfig) InsertAllowedIP(ip net.IPNet) (updated bool) {
	for _, allowedIP := range p.AllowedIPs {
		if cidr.Equal(&allowedIP, &ip) {
			return false
		}
	}

	p.AllowedIPs = append(p.AllowedIPs, ip)
	return true
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This package contains the agent code used to configure the WireGuard tunnel
// between nodes. The code supports adding and removing peers at run-time
// and the peer information is retrieved via the CiliumNode object.
package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/go-openapi/strfmt"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	k8sLabels "k8s.io/apimachinery/pkg/labels"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/clustermesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/wireguard/mode"
	"github.com/cilium/cilium/pkg/wireguard/types"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

const (
	listenPort = 51871
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "wireguard")

// Agent needs to be initialized with Init(). In Init(), the WireGuard tunnel
// device will be created and the proper routes set.  During Init(), existing
// peer keys are placed into `restoredPubKeys`.  Once RestoreFinished() is
// called obsolete keys and peers are removed.  UpdatePeer() inserts or updates
// the public key of peer discovered via the node manager.
type Agent struct {
	lock.RWMutex

	wgClient   mode.WireguardClient
	ipCache    *ipcache.IPCache
	listenPort int
	privKey    wgtypes.Key

	mode mode.WireGuardManager

	cleanup []func()

	// initialized in InitLocalNodeFromWireGuard
	optOut bool
}

// NewAgent creates a new WireGuard Agent
func NewAgent(privKeyPath string, clientset k8sClient.Clientset) (*Agent, error) {
	key, err := loadOrGeneratePrivKey(privKeyPath)
	if err != nil {
		return nil, err
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	a := &Agent{
		wgClient:   wgClient,
		privKey:    key,
		listenPort: listenPort,

		cleanup: []func(){},
	}

	if option.Config.WireguardTopology != "" { // hub-spoke
		a.mode = mode.NewMulHubSpoke(wgClient, clientset)
	} else {
		a.mode = mode.NewP2P(wgClient)
	}

	return a, nil
}

func (a *Agent) Name() string {
	return "wireguard-agent"
}

// Close is called when the agent stops
func (a *Agent) Close() error {
	a.RLock()
	defer a.RUnlock()

	for _, cleanup := range a.cleanup {
		cleanup()
	}

	return a.wgClient.Close()
}

// InitLocalNodeFromWireGuard configures the fields on the local node. Called from
// the LocalNodeSynchronizer _before_ the local node is published in the K8s
// CiliumNode CRD or the kvstore.
//
// This method does the following:
//   - It sets the local WireGuard public key (to be read by other nodes).
//   - It reads the local node's labels to determine if the local node wants to
//     opt-out of node-to-node encryption.
//   - If the local node opts out of node-to-node encryption, we set the
//     localNode.EncryptKey to zero. This indicates to other nodes that they
//     should not encrypt node-to-node traffic with us.
func (a *Agent) InitLocalNodeFromWireGuard(localNode *node.LocalNode) {
	a.Lock()
	defer a.Unlock()

	log.Debug("Initializing local node store with WireGuard public key and settings")

	localNode.EncryptionKey = types.StaticEncryptKey
	localNode.WireguardPubKey = a.privKey.PublicKey().String()
	localNode.Annotations[annotation.WireguardPubKey] = localNode.WireguardPubKey

	if option.Config.EncryptNode && option.Config.NodeEncryptionOptOutLabels.Matches(k8sLabels.Set(localNode.Labels)) {
		log.WithField(logfields.Selector, option.Config.NodeEncryptionOptOutLabels).
			Infof("Opting out from node-to-node encryption on this node as per '%s' label selector",
				option.NodeEncryptionOptOutLabels)
		localNode.OptOutNodeEncryption = true
		localNode.EncryptionKey = 0
	}

	a.optOut = localNode.OptOutNodeEncryption
}

func (a *Agent) initUserspaceDevice(linkMTU int) (netlink.Link, error) {
	log.WithField(logfields.Hint,
		"It is highly recommended to use the kernel implementation. "+
			"See https://www.wireguard.com/install/ for details.").
		Info("falling back to the WireGuard userspace implementation.")

	tundev, err := tun.CreateTUN(types.IfaceName, linkMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create tun device: %w", err)
	}

	uapiSocket, err := ipc.UAPIOpen(types.IfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to create uapi socket: %w", err)
	}

	uapiServer, err := ipc.UAPIListen(types.IfaceName, uapiSocket)
	if err != nil {
		return nil, fmt.Errorf("failed to start WireGuard UAPI server: %w", err)
	}

	scopedLog := log.WithField(logfields.LogSubsys, "wireguard-userspace")
	logger := &device.Logger{
		Verbosef: scopedLog.Debugf,
		Errorf:   scopedLog.Errorf,
	}
	dev := device.NewDevice(tundev, conn.NewDefaultBind(), logger)

	// cleanup removes the tun device and uapi socket
	a.cleanup = append(a.cleanup, func() {
		uapiServer.Close()
		dev.Close()
	})

	go func() {
		for {
			conn, err := uapiServer.Accept()
			if err != nil {
				scopedLog.WithError(err).
					Error("failed to handle WireGuard userspace connection")
				return
			}
			go dev.IpcHandle(conn)
		}
	}()

	link, err := netlink.LinkByName(types.IfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain link: %w", err)
	}

	return link, err
}

// Init creates and configures the local WireGuard tunnel device.
func (a *Agent) Init(ipcache *ipcache.IPCache, mtuConfig mtu.MTU) error {
	addIPCacheListener := false
	a.Lock()
	a.ipCache = ipcache
	defer func() {
		// IPCache will call back into OnIPIdentityCacheChange which requires
		// us to release a.mutex before we can add ourself as a listener.
		a.Unlock()
		if addIPCacheListener {
			a.ipCache.AddListener(a)
		}
	}()

	linkMTU := mtuConfig.GetDeviceMTU() - mtu.WireguardOverhead

	// try to remove any old tun devices created by userspace mode
	link, _ := netlink.LinkByName(types.IfaceName)
	if _, isTuntap := link.(*netlink.Tuntap); isTuntap {
		_ = netlink.LinkDel(link)
	}

	link = &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name: types.IfaceName,
			MTU:  linkMTU,
		},
	}

	err := netlink.LinkAdd(link)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		if !errors.Is(err, unix.EOPNOTSUPP) {
			return fmt.Errorf("failed to add WireGuard device: %w", err)
		}

		if !option.Config.EnableWireguardUserspaceFallback {
			return fmt.Errorf("WireGuard not supported by the Linux kernel (netlink: %w). "+
				"Please upgrade your kernel, manually install the kernel module "+
				"(https://www.wireguard.com/install/), or set enable-wireguard-userspace-fallback=true", err)
		}

		link, err = a.initUserspaceDevice(linkMTU)
		if err != nil {
			return fmt.Errorf("WireGuard userspace: %w", err)
		}
	}

	if option.Config.EnableIPv4 {
		if err := sysctl.Disable(fmt.Sprintf("net.ipv4.conf.%s.rp_filter", types.IfaceName)); err != nil {
			return fmt.Errorf("failed to disable rp_filter: %w", err)
		}
	}

	fwMark := linux_defaults.MagicMarkWireGuardEncrypted
	cfg := wgtypes.Config{
		PrivateKey:   &a.privKey,
		ListenPort:   &a.listenPort,
		ReplacePeers: false,
		FirewallMark: &fwMark,
	}
	if err := a.wgClient.ConfigureDevice(types.IfaceName, cfg); err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %w", err)
	}

	// set MTU again explicitly in case we are re-using an existing device
	if err := netlink.LinkSetMTU(link, linkMTU); err != nil {
		return fmt.Errorf("failed to set mtu: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set link up: %w", err)
	}

	err = a.mode.Init(ipcache)
	if err != nil {
		return err
	}

	// Delete IP rules and routes installed by the agent to steer a traffic from
	// a pod into the WireGuard tunnel device. The rules were used in Cilium
	// versions < 1.13.
	deleteObsoleteIPRules()

	// this is read by the defer statement above
	addIPCacheListener = true

	return nil
}

func (a *Agent) RestoreFinished(cm *clustermesh.ClusterMesh) error {
	if cm != nil {
		// Wait until we received the initial list of nodes from all remote clusters,
		// otherwise we might remove valid peers and disrupt existing connections.
		cm.NodesSynced(context.Background())
	}

	a.Lock()
	defer a.Unlock()

	err := a.mode.RestoreFinished()
	if err != nil {
		return err
	}
	return nil
}

func (a *Agent) UpdatePeer(nodeName, pubKeyHex string, nodeIPv4, nodeIPv6 net.IP) error {
	// To avoid running into a deadlock, we need to lock the IPCache before
	// calling a.Lock(), because IPCache might try to call into
	// OnIPIdentityCacheChange concurrently
	a.ipCache.RLock()
	defer a.ipCache.RUnlock()

	a.Lock()
	defer a.Unlock()

	return a.mode.UpdatePeer(nodeName, pubKeyHex, nodeIPv4, nodeIPv6)
}

func (a *Agent) DeletePeer(nodeName string) error {
	a.Lock()
	defer a.Unlock()
	return a.mode.DeletePeer(nodeName)
}

func loadOrGeneratePrivKey(filePath string) (key wgtypes.Key, err error) {
	bytes, err := os.ReadFile(filePath)
	if os.IsNotExist(err) {
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("failed to generate wg private key: %w", err)
		}

		err = os.WriteFile(filePath, key[:], 0600)
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("failed to save wg private key: %w", err)
		}

		return key, nil
	} else if err != nil {
		return wgtypes.Key{}, fmt.Errorf("failed to load wg private key: %w", err)
	}

	return wgtypes.NewKey(bytes)
}

// OnIPIdentityCacheChange implements ipcache.IPIdentityMappingListener
func (a *Agent) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP,
	oldID *ipcache.Identity, newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata) {
	// This function is invoked from the IPCache with the
	// ipcache.IPIdentityCache lock held. We therefore need to be careful when
	// calling into ipcache.IPIdentityCache from Agent to avoid potential
	// deadlocks.
	a.Lock()
	defer a.Unlock()
	a.mode.OnIPIdentityCacheChange(modType, cidrCluster, oldHostIP, newHostIP, oldID, newID, encryptKey, k8sMeta)
}

// Status returns the state of the WireGuard tunnel managed by this instance.
// If withPeers is true, then the details about each connected peer are
// are populated as well.
func (a *Agent) Status(withPeers bool) (*models.WireguardStatus, error) {
	a.Lock()
	dev, err := a.wgClient.Device(types.IfaceName)
	a.Unlock()

	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	var peers []*models.WireguardPeer
	if withPeers {
		peers = make([]*models.WireguardPeer, 0, len(dev.Peers))
		for _, p := range dev.Peers {
			allowedIPs := make([]string, 0, len(p.AllowedIPs))
			for _, ip := range p.AllowedIPs {
				allowedIPs = append(allowedIPs, ip.String())
			}

			peer := &models.WireguardPeer{
				PublicKey:         p.PublicKey.String(),
				Endpoint:          p.Endpoint.String(),
				LastHandshakeTime: strfmt.DateTime(p.LastHandshakeTime),
				AllowedIps:        allowedIPs,
				TransferTx:        p.TransmitBytes,
				TransferRx:        p.ReceiveBytes,
			}
			peers = append(peers, peer)
		}
	}

	var nodeEncryptionStatus = "Disabled"
	if option.Config.EncryptNode {
		if a.optOut {
			nodeEncryptionStatus = "OptedOut"
		} else {
			nodeEncryptionStatus = "Enabled"
		}
	}

	status := &models.WireguardStatus{
		NodeEncryption: nodeEncryptionStatus,
		Interfaces: []*models.WireguardInterface{{
			Name:       dev.Name,
			ListenPort: int64(dev.ListenPort),
			PublicKey:  dev.PublicKey.String(),
			PeerCount:  int64(len(dev.Peers)),
			Peers:      peers,
		}},
	}

	return status, nil
}

// Removes < v1.13 IP rules and routes.
func deleteObsoleteIPRules() {
	rule := route.Rule{
		Priority: linux_defaults.RulePriorityWireguard,
		Mark:     linux_defaults.RouteMarkEncrypt,
		Mask:     linux_defaults.RouteMarkMask,
		Table:    linux_defaults.RouteTableWireguard,
	}
	rt := route.Route{
		Device: types.IfaceName,
		Table:  linux_defaults.RouteTableWireguard,
	}
	if option.Config.EnableIPv4 {
		route.DeleteRule(netlink.FAMILY_V4, rule)

		subnet := net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 8*net.IPv4len),
		}
		rt.Prefix = subnet
		route.Delete(rt)
	}
	if option.Config.EnableIPv6 {
		route.DeleteRule(netlink.FAMILY_V6, rule)

		subnet := net.IPNet{
			IP:   net.IPv6zero,
			Mask: net.CIDRMask(0, 8*net.IPv6len),
		}
		rt.Prefix = subnet
		route.Delete(rt)
	}
}

package mode

import (
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/wireguard/types"
	"github.com/sirupsen/logrus"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	listenPort = 51871
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "wireguard")

type P2P struct {
	wgClient WireguardClient
	ipCache  *ipcache.IPCache

	// initialized in InitLocalNodeFromWireGuard
	peerByNodeName   map[string]*PeerConfig
	nodeNameByNodeIP map[string]string
	nodeNameByPubKey map[wgtypes.Key]string
	restoredPubKeys  map[wgtypes.Key]struct{}
}

func NewP2P(wgClient WireguardClient) WireGuardManager {
	return &P2P{
		wgClient:         wgClient,
		peerByNodeName:   map[string]*PeerConfig{},
		nodeNameByNodeIP: map[string]string{},
		nodeNameByPubKey: map[wgtypes.Key]string{},
		restoredPubKeys:  map[wgtypes.Key]struct{}{},
	}

}
func (a *P2P) GetPeer(name string) *PeerConfig {
	return a.peerByNodeName[name]
}

func (a *P2P) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP,
	_ *ipcache.Identity, _ ipcache.Identity, _ uint8, _ *ipcache.K8sMetadata) {
	ipnet := cidrCluster.AsIPNet()

	// We are only interested in IPCache entries where the hostIP is set, i.e.
	// updates with oldHostIP set for deleted entries and newHostIP set
	// for newly created entries.
	// A special case (i.e. an entry without a hostIP) is the remote node entry
	// itself when node-to-node encryption is enabled. We handle that case in
	// UpdatePeer(), i.e. we add any required remote node IPs to AllowedIPs
	// there.
	// If we do not find a WireGuard peer for a given hostIP, we intentionally
	// ignore the IPCache upserts here. We instead assume that UpdatePeer() will
	// eventually be called once a node starts participating in WireGuard
	// (or if its host IP changed). UpdatePeer initializes the allowedIPs
	// of newly discovered hostIPs by querying the IPCache, which will contain
	// all updates we might have skipped here before the hostIP was known.
	//
	// Note that we also ignore encryptKey here - it is only used by the
	// datapath. We only ever add AllowedIPs based on IPCache updates for nodes
	// which for which we already know the public key. If a node opts out of
	// encryption, it will not announce it's public key and thus will not be
	// part of the nodeNameByNodeIP map.
	var updatedPeer *PeerConfig
	switch {
	case modType == ipcache.Delete && oldHostIP != nil:
		if nodeName, ok := a.nodeNameByNodeIP[oldHostIP.String()]; ok {
			if peer := a.peerByNodeName[nodeName]; peer != nil {
				if peer.RemoveAllowedIP(ipnet) {
					updatedPeer = peer
				}
			}
		}
	case modType == ipcache.Upsert && newHostIP != nil:
		if nodeName, ok := a.nodeNameByNodeIP[newHostIP.String()]; ok {
			if peer := a.peerByNodeName[nodeName]; peer != nil {
				if peer.InsertAllowedIP(ipnet) {
					updatedPeer = peer
				}
			}
		}
	}

	if updatedPeer != nil {
		if err := a.updatePeerByConfig(updatedPeer); err != nil {
			log.WithFields(logrus.Fields{
				logfields.Modification: modType,
				logfields.IPAddr:       ipnet.String(),
				logfields.OldNode:      oldHostIP,
				logfields.NewNode:      newHostIP,
				logfields.PubKey:       updatedPeer.PubKey,
			}).WithError(err).
				Error("Failed to update WireGuard peer after ipcache update")
		}
	}
}

func (a *P2P) RestoreFinished() error {
	// Delete obsolete peers
	for _, p := range a.peerByNodeName {
		delete(a.restoredPubKeys, p.PubKey)
	}
	for pubKey := range a.restoredPubKeys {
		log.WithField(logfields.PubKey, pubKey).Info("Removing obsolete peer")
		if err := a.deletePeerByPubKey(pubKey); err != nil {
			return err
		}
	}

	a.restoredPubKeys = nil

	log.Debug("Finished restore")

	return nil
}

func (a *P2P) Init(ipcache *ipcache.IPCache) error {
	a.ipCache = ipcache
	dev, err := a.wgClient.Device(types.IfaceName)
	if err != nil {
		return fmt.Errorf("failed to obtain WireGuard device: %w", err)
	}
	for _, peer := range dev.Peers {
		a.restoredPubKeys[peer.PublicKey] = struct{}{}
	}
	return nil
}

func (a *P2P) DeletePeer(nodeName string) error {
	peer := a.peerByNodeName[nodeName]
	if peer == nil {
		return fmt.Errorf("cannot find peer for %q node", nodeName)
	}

	if err := a.deletePeerByPubKey(peer.PubKey); err != nil {
		return err
	}

	delete(a.peerByNodeName, nodeName)
	delete(a.nodeNameByPubKey, peer.PubKey)

	if peer.NodeIPv4 != nil {
		delete(a.nodeNameByNodeIP, peer.NodeIPv4.String())
	}
	if peer.NodeIPv6 != nil {
		delete(a.nodeNameByNodeIP, peer.NodeIPv6.String())
	}

	return nil
}

func (a *P2P) UpdatePeer(nodeName, pubKeyHex string, nodeIPv4, nodeIPv6 net.IP) error {
	pubKey, err := wgtypes.ParseKey(pubKeyHex)
	if err != nil {
		return err
	}

	if prevNodeName, ok := a.nodeNameByPubKey[pubKey]; ok {
		if nodeName != prevNodeName {
			return fmt.Errorf("detected duplicate public key. "+
				"node %q uses same key as existing node %q", nodeName, prevNodeName)
		}
	}

	var allowedIPs []net.IPNet = nil
	if prev := a.peerByNodeName[nodeName]; prev != nil {
		// Handle pubKey change
		if prev.PubKey != pubKey {
			log.WithField(logfields.NodeName, nodeName).Debug("Pubkey has changed")
			// pubKeys differ, so delete old peer
			if err := a.deletePeerByPubKey(prev.PubKey); err != nil {
				return err
			}
		}

		// Reuse allowedIPs from existing peer config
		allowedIPs = prev.AllowedIPs

		// Handle Node IP change
		if !prev.NodeIPv4.Equal(nodeIPv4) {
			delete(a.nodeNameByNodeIP, prev.NodeIPv4.String())
			allowedIPs = nil // reset allowedIPs and re-initialize below
		}
		if !prev.NodeIPv6.Equal(nodeIPv6) {
			delete(a.nodeNameByNodeIP, prev.NodeIPv6.String())
			allowedIPs = nil // reset allowedIPs and re-initialize below
		}
	}

	if allowedIPs == nil {
		// (Re-)Initialize the allowedIPs list by querying the IPCache. The
		// allowedIPs will be updated by OnIPIdentityCacheChange after this
		// function returns.
		var lookupIPv4, lookupIPv6 net.IP
		if option.Config.EnableIPv4 && nodeIPv4 != nil {
			lookupIPv4 = nodeIPv4
			allowedIPs = append(allowedIPs, net.IPNet{
				IP:   nodeIPv4,
				Mask: net.CIDRMask(net.IPv4len*8, net.IPv4len*8),
			})
		}
		if option.Config.EnableIPv6 && nodeIPv6 != nil {
			lookupIPv6 = nodeIPv6
			allowedIPs = append(allowedIPs, net.IPNet{
				IP:   nodeIPv6,
				Mask: net.CIDRMask(net.IPv6len*8, net.IPv6len*8),
			})
		}
		fmt.Println(a.ipCache)
		allowedIPs = append(allowedIPs, a.ipCache.LookupByHostRLocked(lookupIPv4, lookupIPv6)...)
	}

	ep := ""
	if option.Config.EnableIPv4 && nodeIPv4 != nil {
		ep = net.JoinHostPort(nodeIPv4.String(), strconv.Itoa(listenPort))
	} else if option.Config.EnableIPv6 && nodeIPv6 != nil {
		ep = net.JoinHostPort(nodeIPv6.String(), strconv.Itoa(listenPort))
	} else {
		return fmt.Errorf("missing node IP for node %q", nodeName)
	}

	epAddr, err := net.ResolveUDPAddr("udp", ep)
	if err != nil {
		return fmt.Errorf("failed to resolve peer endpoint address: %w", err)
	}

	peer := &PeerConfig{
		PubKey:     pubKey,
		Endpoint:   epAddr,
		NodeIPv4:   nodeIPv4,
		NodeIPv6:   nodeIPv6,
		AllowedIPs: allowedIPs,
	}

	log.WithFields(logrus.Fields{
		logfields.NodeName: nodeName,
		logfields.PubKey:   pubKeyHex,
		logfields.NodeIPv4: nodeIPv4,
		logfields.NodeIPv6: nodeIPv6,
	}).Debug("Updating peer")

	if err := a.updatePeerByConfig(peer); err != nil {
		return err
	}

	a.peerByNodeName[nodeName] = peer
	a.nodeNameByPubKey[pubKey] = nodeName
	if nodeIPv4 != nil {
		a.nodeNameByNodeIP[nodeIPv4.String()] = nodeName
	}
	if nodeIPv6 != nil {
		a.nodeNameByNodeIP[nodeIPv6.String()] = nodeName
	}

	return nil
}

// updatePeerByConfig updates the WireGuard kernel peer config based on peerConfig p
func (a *P2P) updatePeerByConfig(p *PeerConfig) error {
	peer := wgtypes.PeerConfig{
		PublicKey:         p.PubKey,
		Endpoint:          p.Endpoint,
		AllowedIPs:        p.AllowedIPs,
		ReplaceAllowedIPs: true,
	}
	if option.Config.WireguardPersistentKeepalive != 0 {
		peer.PersistentKeepaliveInterval = &option.Config.WireguardPersistentKeepalive
	}
	cfg := wgtypes.Config{
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{peer},
	}

	log.WithFields(logrus.Fields{
		logfields.Endpoint: p.Endpoint,
		logfields.PubKey:   p.PubKey,
		logfields.IPAddrs:  p.AllowedIPs,
	}).Debug("Updating peer config")

	return a.wgClient.ConfigureDevice(types.IfaceName, cfg)
}

func (a *P2P) deletePeerByPubKey(pubKey wgtypes.Key) error {
	log.WithField(logfields.PubKey, pubKey).Debug("Removing peer")

	peerCfg := wgtypes.PeerConfig{
		PublicKey: pubKey,
		Remove:    true,
	}

	cfg := &wgtypes.Config{Peers: []wgtypes.PeerConfig{peerCfg}}
	if err := a.wgClient.ConfigureDevice(types.IfaceName, *cfg); err != nil {
		return err
	}

	return nil
}

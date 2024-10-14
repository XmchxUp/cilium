package mode

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/ipcache"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/wireguard/types"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Connectivity struct {
	Areas   []string `yaml:"area"`
	Gateway string   `yaml:"gateway"`
}

type TopologyConfig struct {
	Connectivities []Connectivity `yaml:"Connectivity"`
}

type MulHubSpoke struct {
	wgClient WireguardClient
	ipCache  *ipcache.IPCache

	// initialized in InitLocalNodeFromWireGuard
	peerByNodeName map[string]*PeerConfig
	peerByGateway  map[string]*PeerConfig

	nodeNameByNodeIP map[string]string // record all nodes except your own
	nodeNameByPubKey map[wgtypes.Key]string
	restoredPubKeys  map[wgtypes.Key]struct{}

	areaByNodeIP map[string]string

	clientset k8sClient.Clientset

	mode     string
	config   *TopologyConfig
	area     string
	nodeName string
	gateway  string

	isMasterNode   bool
	masterNodeName string
}

func NewMulHubSpoke(wgClient WireguardClient, clientset k8sClient.Clientset) WireGuardManager {
	m := &MulHubSpoke{
		wgClient:         wgClient,
		peerByNodeName:   map[string]*PeerConfig{},
		peerByGateway:    map[string]*PeerConfig{},
		nodeNameByNodeIP: map[string]string{},
		nodeNameByPubKey: map[wgtypes.Key]string{},
		restoredPubKeys:  map[wgtypes.Key]struct{}{},
		areaByNodeIP:     map[string]string{},
		clientset:        clientset,
	}

	return m
}

func (a *MulHubSpoke) getConfigMap() (*v1.ConfigMap, error) {
	namespace := "kube-system"
	name := "cilium-wireguard-hubspoke"
	configMap, err := a.clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return configMap, nil
}

func (a *MulHubSpoke) loadTopologyConfig() error {
	configMap, err := a.getConfigMap()
	if err != nil {
		return err
	}

	mode, ok := configMap.Data["TopoMode"]
	if !ok {
		return fmt.Errorf("TopoMode not found in ConfigMap")
	}
	a.mode = mode

	connConfig, ok := configMap.Data["TopologyConfigYaml"]
	if !ok {
		return fmt.Errorf("TopologyConfigYaml not found in ConfigMap")
	}

	var config TopologyConfig
	if err := yaml.Unmarshal([]byte(connConfig), &config); err != nil {
		return fmt.Errorf("failed to parse topology config: %w", err)
	}

	a.config = &config
	return nil
}

func (a *MulHubSpoke) isGatewayMatched(gateway string, area string) bool {
	for _, conn := range a.config.Connectivities {
		if conn.Gateway != gateway {
			continue
		}

		for _, ar := range conn.Areas {
			if ar == area {
				return true
			}
		}
	}
	return false
}

func (a *MulHubSpoke) GetPeer(name string) *PeerConfig {
	return a.peerByNodeName[name]
}

func (a *MulHubSpoke) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP,
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

	var hostIP net.IP
	if modType == ipcache.Delete {
		hostIP = oldHostIP
	} else {
		hostIP = newHostIP
	}

	insert := modType == ipcache.Upsert

	updatedPeer := a.getUpdatedPeer(hostIP, ipnet, insert)

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

// getUpdatedPeer returns the peer to update if the IP change requires it.
func (a *MulHubSpoke) getUpdatedPeer(hostIP net.IP, ipnet net.IPNet, insert bool) *PeerConfig {
	if hostIP == nil {
		return nil
	}

	log.Infof("hostIP: %s", hostIP.String())

	nodeName, exists := a.nodeNameByNodeIP[hostIP.String()]
	if !exists {
		return nil
	}
	log.Infof("nodeName: %s", nodeName)

	peer := a.determinePeer(nodeName, hostIP)
	if peer == nil {
		return nil
	}
	log.Infof("found peer: %s", peer.NodeIPv4.String())

	if (insert && peer.InsertAllowedIP(ipnet)) || (!insert && peer.RemoveAllowedIP(ipnet)) {
		return peer
	}
	return nil
}

// FIXME: Assumes no ambiguous, conflicting configurations, e.g. a1,a2->g1 a1,a2,a3->g2
func (a *MulHubSpoke) getGatewayByArea(area string) string {
	for _, conn := range a.config.Connectivities {
		foundCurrentArea := false
		for _, ar := range conn.Areas {
			if ar == a.area {
				foundCurrentArea = true
				break
			}
		}

		if !foundCurrentArea {
			continue
		}

		for _, ar := range conn.Areas {
			if ar == area {
				return conn.Gateway
			}
		}
		return ""
	}
	return ""
}

// determinePeer returns the appropriate peer based on node type and mode
func (a *MulHubSpoke) determinePeer(nodeName string, hostIP net.IP) *PeerConfig {
	area, areaExists := a.areaByNodeIP[hostIP.String()]
	log.Infof("target area: %s", area)
	switch {
	case a.isDefaultMode() && a.isMasterNode:
		return a.peerByNodeName[nodeName]
	case a.isDefaultMode():
		return a.peerByNodeName[a.masterNodeName]
	case a.isGatewayHub():
		return a.peerByNodeName[nodeName]
	case !a.isGatewayHub():
		log.Info("aaa")
		if areaExists && area != "" { // spoke node update
			log.Info("bb")
			return a.peerByGateway[a.getGatewayByArea(area)]
		}
		log.Info("cc")
		return a.peerByNodeName[nodeName]
	default:
		return nil
	}
}

func (a *MulHubSpoke) RestoreFinished() error {
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

func (a *MulHubSpoke) Init(ipcache *ipcache.IPCache) error {
	a.ipCache = ipcache
	dev, err := a.wgClient.Device(types.IfaceName)
	if err != nil {
		return fmt.Errorf("failed to obtain WireGuard device: %w", err)
	}
	for _, peer := range dev.Peers {
		a.restoredPubKeys[peer.PublicKey] = struct{}{}
	}

	err = a.loadTopologyConfig()
	if err != nil {
		return err
	}

	a.nodeName = "kubernetes/" + os.Getenv("K8S_NODE_NAME")
	log.Infof("current node: %s mode: %s\n", a.nodeName, a.mode)

	nodes, err := a.clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, node := range nodes.Items {
		log.Infof("node: %s\n", node.Name)
		for key, val := range node.Labels {
			log.Infof("label: %s:%s\n", key, val)
			if key == "node-role.kubernetes.io/control-plane" {
				a.masterNodeName = "kubernetes/" + node.Name
			}
		}
	}

	a.isMasterNode = a.masterNodeName == a.nodeName

	if !a.isDefaultMode() {
		log.Info("start mul-hub")
		labels, err := a.getNodeLabels(a.nodeName)
		if err != nil {
			return err
		}

		gateway, _ := a.getGatewayLabel(labels)
		a.gateway = gateway

		area, _ := a.getAreaLabel(labels)
		a.area = area
	} else {
		log.Info("start hub")

	}

	log.Infof("current config:%v, area: %s, gateway: %s, nodeName: %s, masterNodeName: %s\n", a.config, a.area, a.gateway, a.nodeName, a.masterNodeName)
	return nil
}

func (a *MulHubSpoke) DeletePeer(nodeName string) error {
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

func (a *MulHubSpoke) handleGatewayHub(nodeName, pubKeyHex string, nodeIPv4, nodeIPv6 net.IP) error {
	log.Info("handleGatewayHub")
	labels, err := a.getNodeLabels(nodeName)
	if err != nil {
		return err
	}

	gateway, _ := a.getGatewayLabel(labels)

	log.Infof("handleGatewayHub: gateway:%s", gateway)

	if gateway == "" { // it's not gateway peer
		area, err := a.getAreaLabel(labels)
		if err != nil {
			log.Warnf("%s not found area label, ignored\n", nodeName)
			return err
		}

		if nodeIPv4 != nil {
			a.areaByNodeIP[nodeIPv4.String()] = area
		}

		if nodeIPv6 != nil {
			a.areaByNodeIP[nodeIPv6.String()] = area
		}

		if !a.isMasterNode && !a.isGatewayMatched(a.gateway, area) {
			log.Warnf("current hub node %s should not configured peer %s\n", a.nodeName, nodeName)
			return nil
		}
	} else {
		// FIXME: gateway peer需要针对master判断？
		log.Infof("isMasterNode: %v, masterNodeName: %s, nodeName:%s", a.isMasterNode, a.masterNodeName, a.nodeName)
		if !a.isMasterNode && a.masterNodeName != nodeName {
			return nil
		}
	}
	return a.updatePeer(nodeName, pubKeyHex, nodeIPv4, nodeIPv6)
}

func (a *MulHubSpoke) getNodeLabels(nodeName string) (map[string]string, error) {
	nameParts := strings.Split(nodeName, "/")
	cleanNodeName := nameParts[len(nameParts)-1]

	peerNode, err := a.clientset.CoreV1().Nodes().Get(context.TODO(), cleanNodeName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return peerNode.Labels, nil
}

func (a *MulHubSpoke) getGatewayLabel(labels map[string]string) (string, error) {
	gateway, ok := labels["gateway"]
	if !ok {
		return "", nil
	}
	return gateway, nil
}

func (a *MulHubSpoke) getAreaLabel(labels map[string]string) (string, error) {
	area, ok := labels["area"]
	if !ok {
		return "", nil
	}
	return area, nil
}

func (a *MulHubSpoke) isGatewayHub() bool {
	return a.gateway != ""
}

// handleSpokeNode current node is spoke
func (a *MulHubSpoke) handleSpokeNode(nodeName, pubKeyHex string, nodeIPv4, nodeIPv6 net.IP) error {
	// 所有 spoke 跟master control-plane
	if a.masterNodeName == nodeName {
		return a.updatePeer(nodeName, pubKeyHex, nodeIPv4, nodeIPv6)
	}

	labels, err := a.getNodeLabels(nodeName)
	if err != nil {
		return err
	}

	area, err := a.getAreaLabel(labels)
	if err == nil {
		if nodeIPv4 != nil {
			a.areaByNodeIP[nodeIPv4.String()] = area
		}

		if nodeIPv6 != nil {
			a.areaByNodeIP[nodeIPv6.String()] = area
		}
	}

	gateway, err := a.getGatewayLabel(labels)
	if err != nil {
		log.Warnf("%s not found gateway label\n", nodeName)
		// // 如果是同一个area 的spoke node设置需要用于后续更新allowed ips
		// if area != "" && a.area == area {
		// 	log.Warnf("found same spoke node(%s) area(%s) label\n", nodeName, area)
		// 	return nil
		// }
		return nil
	}

	if !a.isGatewayMatched(gateway, a.area) {
		log.Warnf("current spoke node %s should not configured peer %s\n", a.nodeName, nodeName)
		return nil
	}

	// TODO: 调整配置wireguard hub 的优先级
	// 先配置非master 的gateway peer
	err = a.updatePeer(nodeName, pubKeyHex, nodeIPv4, nodeIPv6)
	if err != nil {
		return err
	}
	a.peerByGateway[gateway] = a.peerByNodeName[nodeName]
	return nil
}

func (a *MulHubSpoke) newPeerConfig(nodeName string, nodeIPv4, nodeIPv6 net.IP, pubKey wgtypes.Key) (*PeerConfig, error) {
	if prevNodeName, ok := a.nodeNameByPubKey[pubKey]; ok {
		if nodeName != prevNodeName {
			return nil, fmt.Errorf("detected duplicate public key. "+
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
				return nil, err
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
		return nil, fmt.Errorf("missing node IP for node %q", nodeName)
	}

	epAddr, err := net.ResolveUDPAddr("udp", ep)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve peer endpoint address: %w", err)
	}

	peer := &PeerConfig{
		PubKey:     pubKey,
		Endpoint:   epAddr,
		NodeIPv4:   nodeIPv4,
		NodeIPv6:   nodeIPv6,
		AllowedIPs: allowedIPs,
	}
	return peer, nil
}

func (a *MulHubSpoke) updatePeer(nodeName, pubKeyHex string, nodeIPv4, nodeIPv6 net.IP) error {
	pubKey, err := wgtypes.ParseKey(pubKeyHex)
	if err != nil {
		return err
	}

	peer, err := a.newPeerConfig(nodeName, nodeIPv4, nodeIPv6, pubKey)
	if err != nil {
		return err
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

func (a *MulHubSpoke) isDefaultMode() bool {
	return a.mode == "Default"
}

func (a *MulHubSpoke) updateAllowedIP(nodeIPv4, nodeIPv6 net.IP) {
	var masterPeer *PeerConfig

	var allowedIPs []net.IPNet

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
	allowedIPs = append(allowedIPs, a.ipCache.LookupByHostRLocked(lookupIPv4, lookupIPv6)...)

	if peer := a.peerByNodeName[a.masterNodeName]; peer != nil {
		for _, ip := range allowedIPs {
			if peer.InsertAllowedIP(ip) {
				masterPeer = peer
			}
		}
	}

	if masterPeer != nil {
		if err := a.updatePeerByConfig(masterPeer); err != nil {
			log.WithError(err).
				Error("Failed to update WireGuard peer after update allowed ip")
		}
	}
}

func (a *MulHubSpoke) UpdatePeer(nodeName, pubKeyHex string, nodeIPv4, nodeIPv6 net.IP) error {
	log.Infof("%s UpdatePeer peer:%s, masterName: %s mode:%s", a.nodeName, nodeName, a.masterNodeName, a.mode)
	if nodeIPv4 != nil {
		a.nodeNameByNodeIP[nodeIPv4.String()] = nodeName
	}
	if nodeIPv6 != nil {
		a.nodeNameByNodeIP[nodeIPv6.String()] = nodeName
	}

	if a.isDefaultMode() {
		if !a.isMasterNode && nodeName != a.masterNodeName {
			a.updateAllowedIP(nodeIPv4, nodeIPv6)
			return nil
		}
		return a.updatePeer(nodeName, pubKeyHex, nodeIPv4, nodeIPv6)
	} else {
		if a.isGatewayHub() {
			return a.handleGatewayHub(nodeName, pubKeyHex, nodeIPv4, nodeIPv6)
		} else {
			return a.handleSpokeNode(nodeName, pubKeyHex, nodeIPv4, nodeIPv6)
		}
	}
}

// updatePeerByConfig updates the WireGuard kernel peer config based on peerConfig p
func (a *MulHubSpoke) updatePeerByConfig(p *PeerConfig) error {
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

func (a *MulHubSpoke) deletePeerByPubKey(pubKey wgtypes.Key) error {
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

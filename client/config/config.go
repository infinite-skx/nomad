package config

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/nomad/client/lib/cgutil"
	"github.com/hashicorp/nomad/command/agent/host"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/client/state"
	"github.com/hashicorp/nomad/helper"
	"github.com/hashicorp/nomad/helper/pluginutils/loader"
	"github.com/hashicorp/nomad/nomad/structs"
	structsc "github.com/hashicorp/nomad/nomad/structs/config"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/version"
)

var (
	// DefaultEnvDenylist is the default set of environment variables that are
	// filtered when passing the environment variables of the host to a task.
	DefaultEnvDenylist = strings.Join(host.DefaultEnvDenyList, ",")

	// DefaultUserDenylist is the default set of users that tasks are not
	// allowed to run as when using a driver in "user.checked_drivers"
	DefaultUserDenylist = strings.Join([]string{
		"root",
		"Administrator",
	}, ",")

	// DefaultUserCheckedDrivers is the set of drivers we apply the user
	// denylist onto. For virtualized drivers it often doesn't make sense to
	// make this stipulation so by default they are ignored.
	DefaultUserCheckedDrivers = strings.Join([]string{
		"exec",
		"qemu",
		"java",
	}, ",")

	// A mapping of directories on the host OS to attempt to embed inside each
	// task's chroot.
	DefaultChrootEnv = map[string]string{
		"/bin":            "/bin",
		"/etc":            "/etc",
		"/lib":            "/lib",
		"/lib32":          "/lib32",
		"/lib64":          "/lib64",
		"/run/resolvconf": "/run/resolvconf",
		"/sbin":           "/sbin",
		"/usr":            "/usr",

		// embed systemd-resolved paths for systemd-resolved paths:
		// /etc/resolv.conf is a symlink to /run/systemd/resolve/stub-resolv.conf in such systems.
		// In non-systemd systems, this mount is a no-op and the path is ignored if not present.
		"/run/systemd/resolve": "/run/systemd/resolve",
	}
)

// RPCHandler can be provided to the Client if there is a local server
// to avoid going over the network. If not provided, the Client will
// maintain a connection pool to the servers
type RPCHandler interface {
	RPC(method string, args interface{}, reply interface{}) error
}

// Config is used to parameterize and configure the behavior of the client
type Config struct {
	// DevMode controls if we are in a development mode which
	// avoids persistent storage.
	DevMode bool

	// EnableDebug is used to enable debugging RPC endpoints
	// in the absence of ACLs
	EnableDebug bool

	// StateDir is where we store our state
	StateDir string

	// AllocDir is where we store data for allocations
	AllocDir string

	// LogOutput is the destination for logs
	LogOutput io.Writer

	// Logger provides a logger to the client
	Logger log.InterceptLogger

	// Region is the clients region
	Region string

	// Network interface to be used in network fingerprinting
	NetworkInterface string

	// Network speed is the default speed of network interfaces if they can not
	// be determined dynamically.
	//
	// Deprecated since 0.12: https://www.nomadproject.io/docs/upgrade/upgrade-specific#nomad-0-12-0
	NetworkSpeed int

	// CpuCompute is the default total CPU compute if they can not be determined
	// dynamically. It should be given as Cores * MHz (2 Cores * 2 Ghz = 4000)
	CpuCompute int

	// MemoryMB is the default node total memory in megabytes if it cannot be
	// determined dynamically.
	MemoryMB int

	// MaxKillTimeout allows capping the user-specifiable KillTimeout. If the
	// task's KillTimeout is greater than the MaxKillTimeout, MaxKillTimeout is
	// used.
	MaxKillTimeout time.Duration

	// Servers is a list of known server addresses. These are as "host:port"
	Servers []string

	// RPCHandler can be provided to avoid network traffic if the
	// server is running locally.
	RPCHandler RPCHandler

	// Node provides the base node
	Node *structs.Node

	// ClientMaxPort is the upper range of the ports that the client uses for
	// communicating with plugin subsystems over loopback
	ClientMaxPort uint

	// ClientMinPort is the lower range of the ports that the client uses for
	// communicating with plugin subsystems over loopback
	ClientMinPort uint

	// MaxDynamicPort is the largest dynamic port generated
	MaxDynamicPort int

	// MinDynamicPort is the smallest dynamic port generated
	MinDynamicPort int

	// A mapping of directories on the host OS to attempt to embed inside each
	// task's chroot.
	ChrootEnv map[string]string

	// Options provides arbitrary key-value configuration for nomad internals,
	// like fingerprinters and drivers. The format is:
	//
	//	namespace.option = value
	Options map[string]string

	// Version is the version of the Nomad client
	Version *version.VersionInfo

	// ConsulConfig is this Agent's Consul configuration
	ConsulConfig *structsc.ConsulConfig

	// VaultConfig is this Agent's Vault configuration
	VaultConfig *structsc.VaultConfig

	// StatsCollectionInterval is the interval at which the Nomad client
	// collects resource usage stats
	StatsCollectionInterval time.Duration

	// PublishNodeMetrics determines whether nomad is going to publish node
	// level metrics to remote Telemetry sinks
	PublishNodeMetrics bool

	// PublishAllocationMetrics determines whether nomad is going to publish
	// allocation metrics to remote Telemetry sinks
	PublishAllocationMetrics bool

	// TLSConfig holds various TLS related configurations
	TLSConfig *structsc.TLSConfig

	// GCInterval is the time interval at which the client triggers garbage
	// collection
	GCInterval time.Duration

	// GCParallelDestroys is the number of parallel destroys the garbage
	// collector will allow.
	GCParallelDestroys int

	// GCDiskUsageThreshold is the disk usage threshold given as a percent
	// beyond which the Nomad client triggers GC of terminal allocations
	GCDiskUsageThreshold float64

	// GCInodeUsageThreshold is the inode usage threshold given as a percent
	// beyond which the Nomad client triggers GC of the terminal allocations
	GCInodeUsageThreshold float64

	// GCMaxAllocs is the maximum number of allocations a node can have
	// before garbage collection is triggered.
	GCMaxAllocs int

	// LogLevel is the level of the logs to putout
	LogLevel string

	// NoHostUUID disables using the host's UUID and will force generation of a
	// random UUID.
	NoHostUUID bool

	// ACLEnabled controls if ACL enforcement and management is enabled.
	ACLEnabled bool

	// ACLTokenTTL is how long we cache token values for
	ACLTokenTTL time.Duration

	// ACLPolicyTTL is how long we cache policy values for
	ACLPolicyTTL time.Duration

	// DisableRemoteExec disables remote exec targeting tasks on this client
	DisableRemoteExec bool

	// TemplateConfig includes configuration for template rendering
	TemplateConfig *ClientTemplateConfig

	// RPCHoldTimeout is how long an RPC can be "held" before it is errored.
	// This is used to paper over a loss of leadership by instead holding RPCs,
	// so that the caller experiences a slow response rather than an error.
	// This period is meant to be long enough for a leader election to take
	// place, and a small jitter is applied to avoid a thundering herd.
	RPCHoldTimeout time.Duration

	// PluginLoader is used to load plugins.
	PluginLoader loader.PluginCatalog

	// PluginSingletonLoader is a plugin loader that will returns singleton
	// instances of the plugins.
	PluginSingletonLoader loader.PluginCatalog

	// StateDBFactory is used to override stateDB implementations,
	StateDBFactory state.NewStateDBFunc

	// CNIPath is the path used to search for CNI plugins. Multiple paths can
	// be specified with colon delimited
	CNIPath string

	// CNIConfigDir is the directory where CNI network configuration is located. The
	// client will use this path when fingerprinting CNI networks.
	CNIConfigDir string

	// CNIInterfacePrefix is the prefix to use when creating CNI network interfaces. This
	// defaults to 'eth', therefore the first interface created by CNI inside the alloc
	// network will be 'eth0'.
	CNIInterfacePrefix string

	// BridgeNetworkName is the name to use for the bridge created in bridge
	// networking mode. This defaults to 'nomad' if not set
	BridgeNetworkName string

	// BridgeNetworkAllocSubnet is the IP subnet to use for address allocation
	// for allocations in bridge networking mode. Subnet must be in CIDR
	// notation
	BridgeNetworkAllocSubnet string

	// HostVolumes is a map of the configured host volumes by name.
	HostVolumes map[string]*structs.ClientHostVolumeConfig

	// HostNetworks is a map of the conigured host networks by name.
	HostNetworks map[string]*structs.ClientHostNetworkConfig

	// BindWildcardDefaultHostNetwork toggles if the default host network should accept all
	// destinations (true) or only filter on the IP of the default host network (false) when
	// port mapping. This allows Nomad clients with no defined host networks to accept and
	// port forward traffic only matching on the destination port. An example use of this
	// is when a network loadbalancer is utilizing direct server return and the destination
	// address of incomming packets does not match the IP address of the host interface.
	//
	// This configuration is only considered if no host networks are defined.
	BindWildcardDefaultHostNetwork bool

	// CgroupParent is the parent cgroup Nomad should use when managing any cgroup subsystems.
	// Currently this only includes the 'cpuset' cgroup subsystem.
	CgroupParent string

	// ReservableCores if set overrides the set of reservable cores reported in fingerprinting.
	ReservableCores []uint16
}

type ClientTemplateConfig struct {
	FunctionDenylist []string
	DisableSandbox   bool
}

func (c *ClientTemplateConfig) Copy() *ClientTemplateConfig {
	if c == nil {
		return nil
	}

	nc := new(ClientTemplateConfig)
	*nc = *c
	nc.FunctionDenylist = helper.CopySliceString(nc.FunctionDenylist)
	return nc
}

func (c *Config) Copy() *Config {
	nc := new(Config)
	*nc = *c
	nc.Node = nc.Node.Copy()
	nc.Servers = helper.CopySliceString(nc.Servers)
	nc.Options = helper.CopyMapStringString(nc.Options)
	nc.HostVolumes = structs.CopyMapStringClientHostVolumeConfig(nc.HostVolumes)
	nc.ConsulConfig = c.ConsulConfig.Copy()
	nc.VaultConfig = c.VaultConfig.Copy()
	nc.TemplateConfig = c.TemplateConfig.Copy()
	if c.ReservableCores != nil {
		nc.ReservableCores = make([]uint16, len(c.ReservableCores))
		copy(nc.ReservableCores, c.ReservableCores)
	}
	return nc
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Version:                 version.GetVersion(),
		VaultConfig:             structsc.DefaultVaultConfig(),
		ConsulConfig:            structsc.DefaultConsulConfig(),
		LogOutput:               os.Stderr,
		Region:                  "global",
		StatsCollectionInterval: 1 * time.Second,
		TLSConfig:               &structsc.TLSConfig{},
		LogLevel:                "DEBUG",
		GCInterval:              1 * time.Minute,
		GCParallelDestroys:      2,
		GCDiskUsageThreshold:    80,
		GCInodeUsageThreshold:   70,
		GCMaxAllocs:             50,
		NoHostUUID:              true,
		DisableRemoteExec:       false,
		TemplateConfig: &ClientTemplateConfig{
			FunctionDenylist: []string{"plugin"},
			DisableSandbox:   false,
		},
		RPCHoldTimeout:     5 * time.Second,
		CNIPath:            "/opt/cni/bin",
		CNIConfigDir:       "/opt/cni/config",
		CNIInterfacePrefix: "eth",
		HostNetworks:       map[string]*structs.ClientHostNetworkConfig{},
		CgroupParent:       cgutil.DefaultCgroupParent,
		MaxDynamicPort:     structs.DefaultMinDynamicPort,
		MinDynamicPort:     structs.DefaultMaxDynamicPort,
	}
}

// Read returns the specified configuration value or "".
func (c *Config) Read(id string) string {
	return c.Options[id]
}

// ReadDefault returns the specified configuration value, or the specified
// default value if none is set.
func (c *Config) ReadDefault(id string, defaultValue string) string {
	return c.ReadAlternativeDefault([]string{id}, defaultValue)
}

// ReadAlternativeDefault returns the specified configuration value, or the
// specified value if none is set.
func (c *Config) ReadAlternativeDefault(ids []string, defaultValue string) string {
	for _, id := range ids {
		val, ok := c.Options[id]
		if ok {
			return val
		}
	}

	return defaultValue
}

// ReadBool parses the specified option as a boolean.
func (c *Config) ReadBool(id string) (bool, error) {
	val, ok := c.Options[id]
	if !ok {
		return false, fmt.Errorf("Specified config is missing from options")
	}
	bval, err := strconv.ParseBool(val)
	if err != nil {
		return false, fmt.Errorf("Failed to parse %s as bool: %s", val, err)
	}
	return bval, nil
}

// ReadBoolDefault tries to parse the specified option as a boolean. If there is
// an error in parsing, the default option is returned.
func (c *Config) ReadBoolDefault(id string, defaultValue bool) bool {
	val, err := c.ReadBool(id)
	if err != nil {
		return defaultValue
	}
	return val
}

// ReadInt parses the specified option as a int.
func (c *Config) ReadInt(id string) (int, error) {
	val, ok := c.Options[id]
	if !ok {
		return 0, fmt.Errorf("Specified config is missing from options")
	}
	ival, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("Failed to parse %s as int: %s", val, err)
	}
	return ival, nil
}

// ReadIntDefault tries to parse the specified option as a int. If there is
// an error in parsing, the default option is returned.
func (c *Config) ReadIntDefault(id string, defaultValue int) int {
	val, err := c.ReadInt(id)
	if err != nil {
		return defaultValue
	}
	return val
}

// ReadDuration parses the specified option as a duration.
func (c *Config) ReadDuration(id string) (time.Duration, error) {
	val, ok := c.Options[id]
	if !ok {
		return time.Duration(0), fmt.Errorf("Specified config is missing from options")
	}
	dval, err := time.ParseDuration(val)
	if err != nil {
		return time.Duration(0), fmt.Errorf("Failed to parse %s as time duration: %s", val, err)
	}
	return dval, nil
}

// ReadDurationDefault tries to parse the specified option as a duration. If there is
// an error in parsing, the default option is returned.
func (c *Config) ReadDurationDefault(id string, defaultValue time.Duration) time.Duration {
	val, err := c.ReadDuration(id)
	if err != nil {
		return defaultValue
	}
	return val
}

// ReadStringListToMap tries to parse the specified option(s) as a comma separated list.
// If there is an error in parsing, an empty list is returned.
func (c *Config) ReadStringListToMap(keys ...string) map[string]struct{} {
	val := c.ReadAlternativeDefault(keys, "")

	return splitValue(val)
}

// ReadStringListToMapDefault tries to parse the specified option as a comma
// separated list. If there is an error in parsing, an empty list is returned.
func (c *Config) ReadStringListToMapDefault(key, defaultValue string) map[string]struct{} {
	return c.ReadStringListAlternativeToMapDefault([]string{key}, defaultValue)
}

// ReadStringListAlternativeToMapDefault tries to parse the specified options as a comma sparated list.
// If there is an error in parsing, an empty list is returned.
func (c *Config) ReadStringListAlternativeToMapDefault(keys []string, defaultValue string) map[string]struct{} {
	val := c.ReadAlternativeDefault(keys, defaultValue)

	return splitValue(val)
}

// splitValue parses the value as a comma separated list.
func splitValue(val string) map[string]struct{} {
	list := make(map[string]struct{})
	if val != "" {
		for _, e := range strings.Split(val, ",") {
			trimmed := strings.TrimSpace(e)
			list[trimmed] = struct{}{}
		}
	}
	return list
}

// NomadPluginConfig produces the NomadConfig struct which is sent to Nomad plugins
func (c *Config) NomadPluginConfig() *base.AgentConfig {
	return &base.AgentConfig{
		Driver: &base.ClientDriverConfig{
			ClientMinPort: c.ClientMinPort,
			ClientMaxPort: c.ClientMaxPort,
		},
	}
}

// Validate Client Agent Configuration. Returns a multierror.Error. Fields are
// refenced by their snake_case/HCL naming convention to match documentation.
//
// Must be called on an initialized Config such as generated by DefaultConfig.
//
// Many fields that are shared with server agents are not validated here such
// as:
//
//	StateDir
//	AllocDir
//	ConsulConfig
//	VaultConfig
//	StatsCollectionInterval
//	TLSConfig
//	LogLevel
//
// NetworkInterface is not validated.
func (c *Config) Validate() *helper.ValidationResults {
	results := helper.NewValidationResults()

	if c.Region == "" {
		results.AppendErrorf("Missing region")
	} else {
		//TODO Emit warning if region name is not a valid hostname
	}

	if n := c.NetworkSpeed; n < 0 {
		results.AppendErrorf("network_speed must be >= 0 but found: %v", n)
	}

	if n := c.CpuCompute; n < 0 {
		results.AppendErrorf("cpu_total_compute must be >= 0 but found: %v", n)
	}

	if n := c.MemoryMB; n < 0 {
		results.AppendErrorf("memory_total_mb must be >= 0 but found: %v", n)
	}

	if n := c.MaxKillTimeout; n < 0 {
		results.AppendErrorf("max_kill_timeout must be >= 0 but found: %v", n)
	}

	for i, s := range c.Servers {
		_, _, err := net.SplitHostPort(s)
		if err == nil {
			continue
		}
		results.AppendErrorf("servers[%d] invalid: %v", i, err)
	}

	c.validateNode(results, c.Node)

	if c.MaxDynamicPort > structs.MaxValidPort {
		results.AppendErrorf("max_dynamic_port must be <= %d but found %d", structs.MaxValidPort, c.MaxDynamicPort)
	}

	if c.MaxDynamicPort == 0 {
		results.AppendErrorf("max_dynamic_port must be > 0")
	}

	if c.MinDynamicPort > structs.MaxValidPort {
		results.AppendErrorf("min_dynamic_port must be <= %d but found %d", structs.MaxValidPort, c.MinDynamicPort)
	}

	if c.MinDynamicPort == 0 {
		results.AppendErrorf("min_dynamic_port must be > 0")
	}

	if c.MinDynamicPort > c.MaxDynamicPort {
		results.AppendErrorf("min_dynamic_port (%d) must be < max_dynamic_port (%d)", c.MinDynamicPort, c.MaxDynamicPort)
	}

	//TODO Validate ChrootEnv

	if c.GCInterval <= 0 {
		results.AppendErrorf("gc_interval must be > 0 but found %s", c.GCInterval)
	}

	if c.GCParallelDestroys <= 0 {
		results.AppendErrorf("gc_parallel_destroys must be > 0 but found %d", c.GCParallelDestroys)
	}

	if c.GCDiskUsageThreshold <= 0 {
		results.AppendErrorf("gc_disk_usage_threshold must be > 0 but found %f", c.GCDiskUsageThreshold)
	}

	if c.GCInodeUsageThreshold <= 0 {
		results.AppendErrorf("gc_inode_usage_threshold must be > 0 but found %f", c.GCInodeUsageThreshold)
	}

	if c.GCMaxAllocs <= 0 {
		results.AppendErrorf("gc_max_allocs must be > 0 but found %d", c.GCMaxAllocs)
	}

	panic("TODO start at ACLTokenTTL")

	return results
}

// validateNode validates the subset of structs.Node fields configured for
// client agents.
func (c *Config) validateNode(results *helper.ValidationResults, node *structs.Node) {
	if node == nil {
		// Node should be statically initialized so a failure here is a coding error.
		results.AppendErrorf("Node should be initialized. Please report a bug.")
		return
	}

	if node.Datacenter == "" {
		// Datacenter should be statically initialized so a failure here is a coding error.
		results.AppendErrorf("datacenter must be set.")
	} else {
		//TODO Emit warning if Datacenter is not a valid hostname
	}

	if node.Name == "" {
		results.AppendErrorf("name must be set.")
	}

	if _, _, err := net.SplitHostPort(node.HTTPAddr); err != nil {
		// Should be unreachable due to agent's address normalization,
		// but doesn't hurt to double check.
		results.AppendErrorf("http address invalid: %v", err)
	}

	c.validateNodeReserved(results, node.ReservedResources)
}

// validateNodeReserved validates the node reserved resources for client
// agents.
//
// Node.Reserved is deprecated but until all references are removed it
// should be validated.
func (c *Config) validateNodeReserved(results *helper.ValidationResults, r *structs.NodeReservedResources) {
	if r == nil {
		// Coding error so use Go name for field instead of HCL.
		results.AppendErrorf("Node.ReservedResources must be initialized. Please report a bug")
		return
	}

	if r.Cpu.CpuShares < 0 {
		results.AppendErrorf("reserved.cpu must be >= 0 but found: %d", r.Cpu.CpuShares)
	}

	if c.CpuCompute > 0 && int64(c.CpuCompute) <= r.Cpu.CpuShares {
		//TODO Elevate to error post-1.2.x
		results.AppendWarning("reserved.cpu >= cpu_total_compute: node will be ineligible for new work until fixed (this warning may become a fatal error in the future)")
	}

	// ReservedCpuCores is validated by the Agent

	if r.Memory.MemoryMB < 0 {
		results.AppendErrorf("reserved.memory must be >= 0 but found: %d", r.Memory.MemoryMB)
	}

	if c.MemoryMB > 0 && int64(c.MemoryMB) <= r.Memory.MemoryMB {
		//TODO Elevate to error post-1.2.x
		results.AppendWarning("reserved.memory >= memory_total_mb: node will be ineligible for new work until fixed (this warning may become a fatal error in the future)")
	}

	if r.Disk.DiskMB < 0 {
		results.AppendErrorf("reserved.disk must be >= 0 but found: %d", r.Disk.DiskMB)
	}

	if ports := r.Networks.ReservedHostPorts; ports != "" {
		if _, err := structs.ParsePortRanges(ports); err != nil {
			results.AppendErrorf("reserved.reserved_ports %q invalid: %w", ports, err)
		}
	}
}

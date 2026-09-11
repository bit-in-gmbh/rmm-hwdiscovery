package hwdiscovery

// Inventory is the platform-neutral hardware inventory returned by Discover.
// Empty or unavailable sections are omitted when encoded as JSON.
type Inventory struct {
	System          *System          `json:"system,omitempty"`
	Memory          *Memory          `json:"memory,omitempty"`
	Processors      []Processor      `json:"processors,omitempty"`
	Disks           []Disk           `json:"disks,omitempty"`
	NetworkAdapters []NetworkAdapter `json:"network_adapters,omitempty"`
	GPUs            []GPU            `json:"gpus,omitempty"`
}

// System describes the computer product and its optional platform components.
type System struct {
	Manufacturer string     `json:"manufacturer,omitempty"`
	Model        string     `json:"model,omitempty"`
	Family       string     `json:"family,omitempty"`
	Version      string     `json:"version,omitempty"`
	SerialNumber string     `json:"serial_number,omitempty"`
	UUID         string     `json:"uuid,omitempty"`
	SKU          string     `json:"sku,omitempty"`
	SystemType   string     `json:"system_type,omitempty"`
	Chassis      *Chassis   `json:"chassis,omitempty"`
	Baseboard    *Baseboard `json:"baseboard,omitempty"`
	Firmware     *Firmware  `json:"firmware,omitempty"`
}

// Chassis describes the physical enclosure.
type Chassis struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	AssetTag     string `json:"asset_tag,omitempty"`
	Type         string `json:"type,omitempty"`
}

// Baseboard describes the system's primary circuit board.
type Baseboard struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product,omitempty"`
	Version      string `json:"version,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
}

// Firmware describes the system firmware. ReleaseDate uses YYYY-MM-DD.
type Firmware struct {
	Vendor      string `json:"vendor,omitempty"`
	Version     string `json:"version,omitempty"`
	ReleaseDate string `json:"release_date,omitempty"`
}

// Processor describes one physical processor package. MaxClockMHz is the
// manufacturer's maximum clock rate, not a live measurement.
type Processor struct {
	ID                    string `json:"id,omitempty"`
	Manufacturer          string `json:"manufacturer,omitempty"`
	Model                 string `json:"model,omitempty"`
	Architecture          string `json:"architecture,omitempty"`
	Socket                string `json:"socket,omitempty"`
	PhysicalCoreCount     uint32 `json:"physical_core_count,omitempty"`
	LogicalProcessorCount uint32 `json:"logical_processor_count,omitempty"`
	MaxClockMHz           uint32 `json:"max_clock_mhz,omitempty"`
}

// Memory describes installed physical memory. InstalledPhysicalBytes is the
// operating system's total visible physical memory in exact bytes.
type Memory struct {
	InstalledPhysicalBytes uint64         `json:"installed_physical_bytes,omitempty"`
	Modules                []MemoryModule `json:"modules,omitempty"`
}

// MemoryModule describes one physical memory device. Speed fields are memory
// transfers per second in millions (MT/s), not MHz.
type MemoryModule struct {
	Bank               string `json:"bank,omitempty"`
	Location           string `json:"location,omitempty"`
	Vendor             string `json:"vendor,omitempty"`
	PartNumber         string `json:"part_number,omitempty"`
	SerialNumber       string `json:"serial_number,omitempty"`
	CapacityBytes      uint64 `json:"capacity_bytes,omitempty"`
	ConfiguredSpeedMTs uint32 `json:"configured_speed_mts,omitempty"`
	RatedSpeedMTs      uint32 `json:"rated_speed_mts,omitempty"`
	MemoryType         string `json:"memory_type,omitempty"`
	FormFactor         string `json:"form_factor,omitempty"`
}

// Disk describes one physical storage device. Index is a pointer so the valid
// hardware index zero remains distinguishable from an unavailable index.
type Disk struct {
	ID                      string      `json:"id,omitempty"`
	Index                   *uint32     `json:"index,omitempty"`
	PNPID                   string      `json:"pnp_id,omitempty"`
	Vendor                  string      `json:"vendor,omitempty"`
	Model                   string      `json:"model,omitempty"`
	SerialNumber            string      `json:"serial_number,omitempty"`
	CapacityBytes           uint64      `json:"capacity_bytes,omitempty"`
	LogicalSectorSizeBytes  uint32      `json:"logical_sector_size_bytes,omitempty"`
	PhysicalSectorSizeBytes uint32      `json:"physical_sector_size_bytes,omitempty"`
	MediaType               string      `json:"media_type,omitempty"`
	BusType                 string      `json:"bus_type,omitempty"`
	PartitionTableType      string      `json:"partition_table_type,omitempty"`
	Partitions              []Partition `json:"partitions,omitempty"`
}

// Partition describes one physical-disk partition.
type Partition struct {
	ID                  string   `json:"id,omitempty"`
	Index               *uint32  `json:"index,omitempty"`
	SizeBytes           uint64   `json:"size_bytes,omitempty"`
	StartingOffsetBytes uint64   `json:"starting_offset_bytes,omitempty"`
	Volumes             []Volume `json:"volumes,omitempty"`
}

// Volume describes a logical volume. CapacityBytes is total capacity; dynamic
// free and used capacity are intentionally not collected. MountPoints is sorted.
type Volume struct {
	ID            string   `json:"id,omitempty"`
	Label         string   `json:"label,omitempty"`
	Filesystem    string   `json:"filesystem,omitempty"`
	CapacityBytes uint64   `json:"capacity_bytes,omitempty"`
	MountPoints   []string `json:"mount_points,omitempty"`
}

// NetworkAdapter describes an adapter positively identified as physical.
// MACAddress, when present, uses uppercase colon-separated hexadecimal octets.
type NetworkAdapter struct {
	ID             string `json:"id,omitempty"`
	Name           string `json:"name,omitempty"`
	Model          string `json:"model,omitempty"`
	Vendor         string `json:"vendor,omitempty"`
	PhysicalMedium string `json:"physical_medium,omitempty"`
	MACAddress     string `json:"mac_address,omitempty"`
	PNPID          string `json:"pnp_id,omitempty"`
}

// GPU describes one graphics controller.
type GPU struct {
	ID             string `json:"id,omitempty"`
	PNPID          string `json:"pnp_id,omitempty"`
	Name           string `json:"name,omitempty"`
	Manufacturer   string `json:"manufacturer,omitempty"`
	VideoProcessor string `json:"video_processor,omitempty"`
}

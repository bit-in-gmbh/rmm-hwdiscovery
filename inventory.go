package hwdiscovery

// Inventory is a platform-neutral snapshot of the static hardware identity and
// configuration returned by [Discover]. Its zero value represents an empty
// inventory. Empty or unavailable sections are omitted when encoded as JSON.
type Inventory struct {
	// System describes the computer and its platform components.
	System *System `json:"system,omitempty"`
	// Memory describes the installed physical memory.
	Memory *Memory `json:"memory,omitempty"`
	// Processors contains physical processor packages, sorted by ID.
	Processors []Processor `json:"processors,omitempty"`
	// Disks contains physical storage devices, sorted by hardware index and ID.
	Disks []Disk `json:"disks,omitempty"`
	// NetworkAdapters contains physical network adapters, sorted by ID.
	NetworkAdapters []NetworkAdapter `json:"network_adapters,omitempty"`
	// GPUs contains graphics controllers, sorted by ID.
	GPUs []GPU `json:"gpus,omitempty"`
}

// System describes the computer product and its optional platform components.
type System struct {
	// Manufacturer is the computer manufacturer's name.
	Manufacturer string `json:"manufacturer,omitempty"`
	// Model is the manufacturer's computer model name or number.
	Model string `json:"model,omitempty"`
	// Family is the manufacturer's product family.
	Family string `json:"family,omitempty"`
	// Version is the manufacturer's computer version or revision.
	Version string `json:"version,omitempty"`
	// SerialNumber is the manufacturer's computer serial number.
	SerialNumber string `json:"serial_number,omitempty"`
	// UUID is the lowercase canonical system UUID.
	UUID string `json:"uuid,omitempty"`
	// SKU is the manufacturer's stock-keeping unit.
	SKU string `json:"sku,omitempty"`
	// SystemType is the normalized system architecture or product type.
	SystemType string `json:"system_type,omitempty"`
	// Chassis describes the physical enclosure when available.
	Chassis *Chassis `json:"chassis,omitempty"`
	// Baseboard describes the primary circuit board when available.
	Baseboard *Baseboard `json:"baseboard,omitempty"`
	// Firmware describes the system firmware when available.
	Firmware *Firmware `json:"firmware,omitempty"`
}

// Chassis describes the physical enclosure.
type Chassis struct {
	// Manufacturer is the enclosure manufacturer's name.
	Manufacturer string `json:"manufacturer,omitempty"`
	// Model is the enclosure model name or number.
	Model string `json:"model,omitempty"`
	// SerialNumber is the enclosure serial number.
	SerialNumber string `json:"serial_number,omitempty"`
	// AssetTag is the organization-assigned enclosure asset tag.
	AssetTag string `json:"asset_tag,omitempty"`
	// Type is the normalized enclosure type, such as "desktop" or "notebook".
	Type string `json:"type,omitempty"`
}

// Baseboard describes the system's primary circuit board.
type Baseboard struct {
	// Manufacturer is the board manufacturer's name.
	Manufacturer string `json:"manufacturer,omitempty"`
	// Product is the board's product name or number.
	Product string `json:"product,omitempty"`
	// Version is the board's version or revision.
	Version string `json:"version,omitempty"`
	// SerialNumber is the board's serial number.
	SerialNumber string `json:"serial_number,omitempty"`
}

// Firmware describes the system firmware.
type Firmware struct {
	// Vendor is the firmware vendor's name.
	Vendor string `json:"vendor,omitempty"`
	// Version is the firmware version.
	Version string `json:"version,omitempty"`
	// ReleaseDate is the firmware release date in YYYY-MM-DD form.
	ReleaseDate string `json:"release_date,omitempty"`
}

// Processor describes one physical processor package.
type Processor struct {
	// ID is the platform-provided or synthesized stable package identifier.
	ID string `json:"id,omitempty"`
	// Manufacturer is the processor manufacturer's name.
	Manufacturer string `json:"manufacturer,omitempty"`
	// Model is the processor model name.
	Model string `json:"model,omitempty"`
	// SerialNumber is the processor package serial number.
	SerialNumber string `json:"serial_number,omitempty"`
	// Architecture is the normalized instruction-set architecture.
	Architecture string `json:"architecture,omitempty"`
	// Socket is the physical socket designation.
	Socket string `json:"socket,omitempty"`
	// PhysicalCoreCount is the number of physical cores in the package.
	PhysicalCoreCount uint32 `json:"physical_core_count,omitempty"`
	// LogicalProcessorCount is the number of logical processors in the package.
	LogicalProcessorCount uint32 `json:"logical_processor_count,omitempty"`
	// MaxClockMHz is the manufacturer's maximum clock rate in MHz, not a live measurement.
	MaxClockMHz uint32 `json:"max_clock_mhz,omitempty"`
}

// Memory describes installed physical memory.
type Memory struct {
	// InstalledPhysicalBytes is the operating system's visible physical memory in exact bytes.
	InstalledPhysicalBytes uint64 `json:"installed_physical_bytes,omitempty"`
	// Modules contains physical memory devices in deterministic platform order.
	Modules []MemoryModule `json:"modules,omitempty"`
}

// MemoryModule describes one physical memory device.
type MemoryModule struct {
	// Bank is the memory bank designation.
	Bank string `json:"bank,omitempty"`
	// Location is the physical device or slot designation.
	Location string `json:"location,omitempty"`
	// Vendor is the module manufacturer's name.
	Vendor string `json:"vendor,omitempty"`
	// PartNumber is the manufacturer's module part number.
	PartNumber string `json:"part_number,omitempty"`
	// SerialNumber is the module serial number.
	SerialNumber string `json:"serial_number,omitempty"`
	// CapacityBytes is the module capacity in exact bytes.
	CapacityBytes uint64 `json:"capacity_bytes,omitempty"`
	// ConfiguredSpeedMTs is the configured transfer rate in millions of transfers per second.
	ConfiguredSpeedMTs uint32 `json:"configured_speed_mts,omitempty"`
	// RatedSpeedMTs is the rated transfer rate in millions of transfers per second.
	RatedSpeedMTs uint32 `json:"rated_speed_mts,omitempty"`
	// MemoryType is the normalized memory technology, such as "ddr5".
	MemoryType string `json:"memory_type,omitempty"`
	// FormFactor is the normalized physical form factor, such as "dimm".
	FormFactor string `json:"form_factor,omitempty"`
}

// Disk describes one physical storage device.
type Disk struct {
	// ID is the platform-provided stable device identifier.
	ID string `json:"id,omitempty"`
	// Index is the hardware index. A nil value means the index is unavailable.
	Index *uint32 `json:"index,omitempty"`
	// PNPID is the platform Plug and Play identifier.
	PNPID string `json:"pnp_id,omitempty"`
	// Vendor is the device manufacturer's name.
	Vendor string `json:"vendor,omitempty"`
	// Model is the device model name or number.
	Model string `json:"model,omitempty"`
	// SerialNumber is the device serial number.
	SerialNumber string `json:"serial_number,omitempty"`
	// CapacityBytes is the device capacity in exact bytes.
	CapacityBytes uint64 `json:"capacity_bytes,omitempty"`
	// LogicalSectorSizeBytes is the logical sector size in exact bytes.
	LogicalSectorSizeBytes uint32 `json:"logical_sector_size_bytes,omitempty"`
	// PhysicalSectorSizeBytes is the physical sector size in exact bytes.
	PhysicalSectorSizeBytes uint32 `json:"physical_sector_size_bytes,omitempty"`
	// MediaType is the normalized medium type, such as "ssd" or "hdd".
	MediaType string `json:"media_type,omitempty"`
	// BusType is the normalized connection type, such as "nvme" or "usb".
	BusType string `json:"bus_type,omitempty"`
	// PartitionTableType is the normalized partition-table type, such as "gpt".
	PartitionTableType string `json:"partition_table_type,omitempty"`
	// Partitions contains the device's partitions, sorted by index and ID.
	Partitions []Partition `json:"partitions,omitempty"`
}

// Partition describes one physical-disk partition.
type Partition struct {
	// ID is the platform-provided stable partition identifier.
	ID string `json:"id,omitempty"`
	// Index is the partition index. A nil value means the index is unavailable.
	Index *uint32 `json:"index,omitempty"`
	// SizeBytes is the partition size in exact bytes.
	SizeBytes uint64 `json:"size_bytes,omitempty"`
	// StartingOffsetBytes is the partition's offset from the start of its disk in exact bytes.
	StartingOffsetBytes uint64 `json:"starting_offset_bytes,omitempty"`
	// Volumes contains logical volumes associated with the partition, sorted by ID.
	Volumes []Volume `json:"volumes,omitempty"`
}

// Volume describes a logical volume.
type Volume struct {
	// ID is the platform-provided stable volume identifier.
	ID string `json:"id,omitempty"`
	// Label is the user-assigned volume label.
	Label string `json:"label,omitempty"`
	// Filesystem is the normalized filesystem type.
	Filesystem string `json:"filesystem,omitempty"`
	// CapacityBytes is the total volume capacity in exact bytes, not free or used capacity.
	CapacityBytes uint64 `json:"capacity_bytes,omitempty"`
	// MountPoints contains the volume's sorted mount paths.
	MountPoints []string `json:"mount_points,omitempty"`
}

// NetworkAdapter describes an adapter positively identified as physical.
type NetworkAdapter struct {
	// ID is the platform-provided stable adapter identifier.
	ID string `json:"id,omitempty"`
	// Name is the adapter's display or interface name.
	Name string `json:"name,omitempty"`
	// Model is the adapter model name or number.
	Model string `json:"model,omitempty"`
	// Vendor is the adapter manufacturer's name.
	Vendor string `json:"vendor,omitempty"`
	// PhysicalMedium is the normalized medium type, such as "ethernet" or "wireless_lan".
	PhysicalMedium string `json:"physical_medium,omitempty"`
	// MACAddress is the uppercase, colon-separated hardware address.
	MACAddress string `json:"mac_address,omitempty"`
	// PNPID is the platform Plug and Play identifier.
	PNPID string `json:"pnp_id,omitempty"`
}

// GPU describes one graphics controller.
type GPU struct {
	// ID is the platform-provided stable controller identifier.
	ID string `json:"id,omitempty"`
	// PNPID is the platform Plug and Play identifier.
	PNPID string `json:"pnp_id,omitempty"`
	// Name is the controller's display name.
	Name string `json:"name,omitempty"`
	// Manufacturer is the controller manufacturer's name.
	Manufacturer string `json:"manufacturer,omitempty"`
	// VideoProcessor is the graphics processor name.
	VideoProcessor string `json:"video_processor,omitempty"`
}

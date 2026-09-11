//go:build windows && (amd64 || arm64)

package hwdiscovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fixtureQueryer struct {
	rows    map[string]any
	errors  map[string]error
	queries []string
}

func (q *fixtureQueryer) Query(_ string, query string, dst any) error {
	class := queryClassName(query)
	q.queries = append(q.queries, class)
	if err := q.errors[class]; err != nil {
		return err
	}
	rows, found := q.rows[class]
	if !found {
		return nil
	}
	reflect.ValueOf(dst).Elem().Set(reflect.ValueOf(rows))
	return nil
}

func queryClassName(query string) string {
	const marker = " FROM "
	index := strings.LastIndex(strings.ToUpper(query), marker)
	if index < 0 {
		return ""
	}
	return strings.TrimSpace(query[index+len(marker):])
}

func pointer[T any](value T) *T { return &value }

func completeFixture() map[string]any {
	releaseDate := time.Date(2026, time.April, 3, 12, 30, 0, 0, time.UTC)
	return map[string]any{
		"Win32_ComputerSystem": []win32ComputerSystem{{
			Manufacturer:        pointer(" Example Corp \x00"),
			Model:               pointer("RoadRunner 15"),
			SystemFamily:        pointer("Mobile"),
			SystemType:          pointer("x64-based PC"),
			TotalPhysicalMemory: pointer(uint64(32 << 30)),
		}},
		"Win32_ComputerSystemProduct": []win32ComputerSystemProduct{{
			Vendor:            pointer("Ignored Vendor"),
			Name:              pointer("Ignored Product"),
			Version:           pointer("Rev 2"),
			IdentifyingNumber: pointer("SYS-123"),
			UUID:              pointer("{ABCDEF12-3456-7890-ABCD-EF1234567890}"),
			SKUNumber:         pointer("SKU-7"),
		}},
		"Win32_SystemEnclosure": []win32SystemEnclosure{{
			Manufacturer:   pointer("Example Corp"),
			Model:          pointer("Shell"),
			SerialNumber:   pointer("CASE-1"),
			SMBIOSAssetTag: pointer("ASSET-9"),
			ChassisTypes:   []int32{9},
		}},
		"Win32_BaseBoard": []win32BaseBoard{{
			Manufacturer: pointer("Boards Ltd"),
			Product:      pointer("Board X"),
			Version:      pointer("1.2"),
			SerialNumber: pointer("BOARD-1"),
		}},
		"Win32_BIOS": []win32BIOS{{
			Manufacturer:      pointer("Firmware Inc"),
			SMBIOSBIOSVersion: pointer("2.4.6"),
			ReleaseDate:       &releaseDate,
		}},
		"Win32_Processor": []win32Processor{
			{DeviceID: pointer("CPU1"), Manufacturer: pointer("Chip Co"), Name: pointer("FastChip"), SerialNumber: pointer("PROCESSOR-B"), Architecture: pointer(uint16(9)), SocketDesignation: pointer("Socket B"), NumberOfCores: pointer(uint32(8)), NumberOfLogicalProcessors: pointer(uint32(16)), MaxClockSpeed: pointer(uint32(4200))},
			{DeviceID: pointer("CPU0"), Manufacturer: pointer("Chip Co"), Name: pointer("FastChip"), SerialNumber: pointer("PROCESSOR-A"), Architecture: pointer(uint16(9)), SocketDesignation: pointer("Socket A"), NumberOfCores: pointer(uint32(8)), NumberOfLogicalProcessors: pointer(uint32(16)), MaxClockSpeed: pointer(uint32(4200))},
		},
		"Win32_PhysicalMemory": []win32PhysicalMemory{
			{BankLabel: pointer("BANK 1"), DeviceLocator: pointer("DIMM_B"), Manufacturer: pointer("Memory Co"), PartNumber: pointer("PART-B"), SerialNumber: pointer("MEM-B"), Capacity: pointer(uint64(16 << 30)), ConfiguredClockSpeed: pointer(uint32(5200)), Speed: pointer(uint32(5600)), SMBIOSMemoryType: pointer(uint32(34)), FormFactor: pointer(uint16(12))},
			{BankLabel: pointer("BANK 0"), DeviceLocator: pointer("DIMM_A"), Manufacturer: pointer("Memory Co"), PartNumber: pointer("PART-A"), SerialNumber: pointer("MEM-A"), Capacity: pointer(uint64(16 << 30)), ConfiguredClockSpeed: pointer(uint32(3200)), Speed: pointer(uint32(3200)), SMBIOSMemoryType: pointer(uint32(26)), FormFactor: pointer(uint16(8))},
		},
		"Win32_DiskDrive": []win32DiskDrive{
			{DeviceID: pointer(`\\.\PHYSICALDRIVE1`), Index: pointer(uint32(1)), PNPDeviceID: pointer(`USBSTOR\DISK1`), Manufacturer: pointer("Disk Co"), Model: pointer("Archive"), SerialNumber: pointer("DISK-B"), Size: pointer(uint64(2_000_000)), BytesPerSector: pointer(uint32(512)), MediaType: pointer("Removable Media"), InterfaceType: pointer("USB")},
			{DeviceID: pointer(`\\.\PHYSICALDRIVE0`), Index: pointer(uint32(0)), PNPDeviceID: pointer(`PCI\DISK0`), Manufacturer: pointer("Disk Co"), Model: pointer("Speedy"), SerialNumber: pointer("DISK-A"), Size: pointer(uint64(1_000_000)), BytesPerSector: pointer(uint32(512)), MediaType: pointer("Fixed hard disk media"), InterfaceType: pointer("IDE")},
		},
		"Win32_DiskPartition": []win32DiskPartition{
			{DeviceID: pointer("Disk #0, Partition #1"), DiskIndex: pointer(uint32(0)), Index: pointer(uint32(1)), Size: pointer(uint64(600_000)), StartingOffset: pointer(uint64(400_000)), Type: pointer("GPT: Basic Data")},
			{DeviceID: pointer("Disk #1, Partition #0"), DiskIndex: pointer(uint32(1)), Index: pointer(uint32(0)), Size: pointer(uint64(2_000_000)), StartingOffset: pointer(uint64(1_024)), Type: pointer("MBR: Installable File System")},
			{DeviceID: pointer("Disk #0, Partition #0"), DiskIndex: pointer(uint32(0)), Index: pointer(uint32(0)), Size: pointer(uint64(400_000)), StartingOffset: pointer(uint64(1_024)), Type: pointer("GPT: System")},
		},
		"Win32_LogicalDiskToPartition": []win32LogicalDiskToPartition{
			{Antecedent: pointer(`Win32_DiskPartition.DeviceID="Disk #1, Partition #0"`), Dependent: pointer(`Win32_LogicalDisk.DeviceID="E:"`)},
			{Antecedent: pointer(`Win32_DiskPartition.DeviceID="Disk #0, Partition #1"`), Dependent: pointer(`Win32_LogicalDisk.DeviceID="D:"`)},
			{Antecedent: pointer(`Win32_DiskPartition.DeviceID="Disk #0, Partition #0"`), Dependent: pointer(`Win32_LogicalDisk.DeviceID="C:"`)},
		},
		"Win32_LogicalDisk": []win32LogicalDisk{
			{DeviceID: pointer("E:"), VolumeName: pointer("Archive"), FileSystem: pointer("exFAT"), Size: pointer(uint64(2_000_000))},
			{DeviceID: pointer("D:"), VolumeName: pointer("Data"), FileSystem: pointer("NTFS"), Size: pointer(uint64(600_000))},
			{DeviceID: pointer("C:"), VolumeName: pointer("System"), FileSystem: pointer("NTFS"), Size: pointer(uint64(400_000))},
		},
		"MSFT_Disk": []msftDisk{
			{Number: pointer(uint32(1)), LogicalSectorSize: pointer(uint32(512)), PhysicalSectorSize: pointer(uint32(4096)), BusType: pointer(uint16(7)), PartitionStyle: pointer(uint16(1))},
			{Number: pointer(uint32(0)), LogicalSectorSize: pointer(uint32(512)), PhysicalSectorSize: pointer(uint32(4096)), BusType: pointer(uint16(17)), PartitionStyle: pointer(uint16(2))},
		},
		"MSFT_PhysicalDisk": []msftPhysicalDisk{
			{DeviceId: pointer("1"), MediaType: pointer(uint16(3)), BusType: pointer(uint16(7))},
			{DeviceId: pointer("0"), MediaType: pointer(uint16(4)), BusType: pointer(uint16(17))},
		},
		"Win32_NetworkAdapter": []win32NetworkAdapter{
			{GUID: pointer("{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"), DeviceID: pointer("2"), PNPDeviceID: pointer(`PCI\NIC-B`), Name: pointer("Wi-Fi"), ProductName: pointer("Wireless 2"), Manufacturer: pointer("Net Co"), MACAddress: pointer("00-11-22-aa-bb-cc"), PhysicalAdapter: pointer(true), AdapterTypeID: pointer(uint16(9))},
			{GUID: pointer("{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"), DeviceID: pointer("1"), PNPDeviceID: pointer(`PCI\NIC-A`), Name: pointer("Ethernet"), ProductName: pointer("Ether 1"), Manufacturer: pointer("Net Co"), MACAddress: pointer("00:11:22:33:44:55"), PhysicalAdapter: pointer(true), AdapterTypeID: pointer(uint16(0))},
			{GUID: pointer("{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}"), DeviceID: pointer("3"), Name: pointer("Virtual"), PhysicalAdapter: pointer(false)},
			{GUID: pointer("{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}"), DeviceID: pointer("4"), Name: pointer("Unconfirmed")},
		},
		"Win32_VideoController": []win32VideoController{
			{DeviceID: pointer("Video1"), PNPDeviceID: pointer(`PCI\GPU-B`), Name: pointer("GPU B"), AdapterCompatibility: pointer("Graphics Co"), VideoProcessor: pointer("Core B")},
			{DeviceID: pointer("Video0"), PNPDeviceID: pointer(`PCI\GPU-A`), Name: pointer("GPU A"), AdapterCompatibility: pointer("Graphics Co"), VideoProcessor: pointer("Core A")},
		},
	}
}

func TestCompleteInventoryMappingAndDeterministicOrder(t *testing.T) {
	first := discover(&fixtureQueryer{rows: completeFixture(), errors: map[string]error{}})
	second := discover(&fixtureQueryer{rows: completeFixture(), errors: map[string]error{}})

	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first result: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second result: %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("discovery is not deterministic\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
	golden, err := os.ReadFile("testdata/complete_inventory.json")
	if err != nil {
		t.Fatalf("read complete-inventory golden file: %v", err)
	}
	var compactGolden bytes.Buffer
	if err := json.Compact(&compactGolden, golden); err != nil {
		t.Fatalf("compact complete-inventory golden file: %v", err)
	}
	if string(firstJSON) != compactGolden.String() {
		t.Fatalf("complete inventory does not match golden fixture\nwant: %s\n got: %s", compactGolden.String(), firstJSON)
	}

	if first.System == nil || first.System.Manufacturer != "Example Corp" || first.System.UUID != "abcdef12-3456-7890-abcd-ef1234567890" || first.System.SystemType != "x86_64" {
		t.Fatalf("unexpected system mapping: %#v", first.System)
	}
	if first.System.Chassis == nil || first.System.Chassis.Type != "laptop" || first.System.Firmware == nil || first.System.Firmware.ReleaseDate != "2026-04-03" {
		t.Fatalf("unexpected platform component mapping: %#v", first.System)
	}
	if len(first.Processors) != 2 || first.Processors[0].ID != "CPU0" || first.Processors[0].SerialNumber != "PROCESSOR-A" || first.Processors[0].Architecture != "x86_64" || first.Processors[0].MaxClockMHz != 4200 {
		t.Fatalf("unexpected processor mapping: %#v", first.Processors)
	}
	if first.Memory == nil || first.Memory.InstalledPhysicalBytes != 32<<30 || len(first.Memory.Modules) != 2 || first.Memory.Modules[0].Location != "DIMM_A" || first.Memory.Modules[0].SerialNumber != "MEM-A" || first.Memory.Modules[0].MemoryType != "ddr4" || first.Memory.Modules[1].ConfiguredSpeedMTs != 5200 {
		t.Fatalf("unexpected memory mapping: %#v", first.Memory)
	}
	if len(first.Disks) != 2 || *first.Disks[0].Index != 0 || first.Disks[0].SerialNumber != "DISK-A" || first.Disks[0].MediaType != "ssd" || first.Disks[0].BusType != "nvme" || first.Disks[0].PartitionTableType != "gpt" || first.Disks[0].PhysicalSectorSizeBytes != 4096 {
		t.Fatalf("unexpected disk mapping: %#v", first.Disks)
	}
	if len(first.Disks[0].Partitions) != 2 || *first.Disks[0].Partitions[0].Index != 0 || len(first.Disks[0].Partitions[0].Volumes) != 1 || first.Disks[0].Partitions[0].Volumes[0].MountPoints[0] != `C:\` {
		t.Fatalf("unexpected storage association mapping: %#v", first.Disks[0].Partitions)
	}
	if len(first.NetworkAdapters) != 2 || first.NetworkAdapters[0].Name != "Ethernet" || first.NetworkAdapters[0].MACAddress != "00:11:22:33:44:55" || first.NetworkAdapters[1].PhysicalMedium != "wireless_lan" {
		t.Fatalf("unexpected physical adapter filtering or normalization: %#v", first.NetworkAdapters)
	}
	if len(first.GPUs) != 2 || first.GPUs[0].Name != "GPU A" {
		t.Fatalf("unexpected GPU mapping: %#v", first.GPUs)
	}
}

func TestNilPropertiesNeverPanic(t *testing.T) {
	rows := map[string]any{
		"Win32_ComputerSystem":         []win32ComputerSystem{{}},
		"Win32_ComputerSystemProduct":  []win32ComputerSystemProduct{{}},
		"Win32_SystemEnclosure":        []win32SystemEnclosure{{}},
		"Win32_BaseBoard":              []win32BaseBoard{{}},
		"Win32_BIOS":                   []win32BIOS{{}},
		"Win32_Processor":              []win32Processor{{}},
		"Win32_PhysicalMemory":         []win32PhysicalMemory{{}},
		"Win32_DiskDrive":              []win32DiskDrive{{}},
		"Win32_DiskPartition":          []win32DiskPartition{{}},
		"Win32_LogicalDiskToPartition": []win32LogicalDiskToPartition{{}},
		"Win32_LogicalDisk":            []win32LogicalDisk{{}},
		"MSFT_Disk":                    []msftDisk{{}},
		"MSFT_PhysicalDisk":            []msftPhysicalDisk{{}},
		"Win32_NetworkAdapter":         []win32NetworkAdapter{{}},
		"Win32_VideoController":        []win32VideoController{{}},
	}
	inventory := discover(&fixtureQueryer{rows: rows, errors: map[string]error{}})
	encoded, err := json.Marshal(inventory)
	if err != nil {
		t.Fatalf("marshal nil-only fixture: %v", err)
	}
	if string(encoded) != `{}` {
		t.Fatalf("nil-only fixture returned JSON data: %s", encoded)
	}
}

func TestQueryFailuresAreIsolated(t *testing.T) {
	tests := []struct {
		name   string
		failed []string
		check  func(*testing.T, Inventory)
	}{
		{
			name:   "processor",
			failed: []string{"Win32_Processor"},
			check: func(t *testing.T, inventory Inventory) {
				if len(inventory.Processors) != 0 || inventory.System == nil || inventory.Memory == nil || len(inventory.Disks) == 0 || len(inventory.NetworkAdapters) == 0 || len(inventory.GPUs) == 0 {
					t.Fatalf("processor failure affected unrelated data: %#v", inventory)
				}
			},
		},
		{
			name:   "system product",
			failed: []string{"Win32_ComputerSystemProduct"},
			check: func(t *testing.T, inventory Inventory) {
				if inventory.System == nil || inventory.System.Manufacturer != "Example Corp" || inventory.System.UUID != "" || inventory.System.Chassis == nil || inventory.Memory == nil || len(inventory.Disks) == 0 {
					t.Fatalf("product failure discarded base system data: %#v", inventory)
				}
			},
		},
		{
			name:   "partition association",
			failed: []string{"Win32_LogicalDiskToPartition"},
			check: func(t *testing.T, inventory Inventory) {
				if len(inventory.Disks) == 0 || len(inventory.Disks[0].Partitions) == 0 || len(inventory.Disks[0].Partitions[0].Volumes) != 0 || inventory.System == nil {
					t.Fatalf("association failure discarded base storage: %#v", inventory.Disks)
				}
			},
		},
		{
			name:   "optional storage enrichment",
			failed: []string{"MSFT_Disk", "MSFT_PhysicalDisk"},
			check: func(t *testing.T, inventory Inventory) {
				if len(inventory.Disks) != 2 || len(inventory.Disks[0].Partitions) != 2 || len(inventory.Disks[0].Partitions[0].Volumes) != 1 || inventory.Disks[0].PhysicalSectorSizeBytes != 0 {
					t.Fatalf("enrichment failure discarded base storage: %#v", inventory.Disks)
				}
			},
		},
		{
			name:   "network",
			failed: []string{"Win32_NetworkAdapter"},
			check: func(t *testing.T, inventory Inventory) {
				if len(inventory.NetworkAdapters) != 0 || inventory.System == nil || len(inventory.Disks) == 0 || len(inventory.GPUs) == 0 {
					t.Fatalf("network failure affected unrelated data: %#v", inventory)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			queryErrors := make(map[string]error, len(test.failed))
			for _, class := range test.failed {
				queryErrors[class] = errors.New("fixture query failure")
			}
			test.check(t, discover(&fixtureQueryer{rows: completeFixture(), errors: queryErrors}))
		})
	}
}

func TestNormalizationAndPlaceholderRemoval(t *testing.T) {
	if value := cleanString("\x00  Default string \x00"); value != "" {
		t.Fatalf("placeholder survived cleanup: %q", value)
	}
	if value := normalizeUUID("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"); value != "" {
		t.Fatalf("placeholder UUID survived cleanup: %q", value)
	}
	if value := normalizeUUID("ABCDEF1234567890ABCDEF1234567890"); value != "abcdef12-3456-7890-abcd-ef1234567890" {
		t.Fatalf("UUID was not canonicalized: %q", value)
	}
	if value := normalizeMAC("a1-b2-c3-d4-e5-f6"); value != "A1:B2:C3:D4:E5:F6" {
		t.Fatalf("MAC was not canonicalized: %q", value)
	}
	if value := normalizeBusType(pointer(uint16(17))); value != "nvme" {
		t.Fatalf("bus type was not normalized: %q", value)
	}
	if value := normalizeDiskMediaType(pointer(uint16(4))); value != "ssd" {
		t.Fatalf("media type was not normalized: %q", value)
	}
	if value := normalizeMemoryType(pointer(uint32(34)), nil); value != "ddr5" {
		t.Fatalf("memory type was not normalized: %q", value)
	}
	if value := normalizeMemoryType(nil, pointer(uint16(20))); value != "ddr" {
		t.Fatalf("legacy memory type was not normalized: %q", value)
	}
}

type panicQueryer struct {
	fixture *fixtureQueryer
	class   string
}

func (q *panicQueryer) Query(namespace, query string, dst any) error {
	if queryClassName(query) == q.class {
		panic("fixture query panic")
	}
	return q.fixture.Query(namespace, query, dst)
}

func TestQueryPanicIsIsolated(t *testing.T) {
	inventory := discover(&panicQueryer{
		fixture: &fixtureQueryer{rows: completeFixture(), errors: map[string]error{}},
		class:   "Win32_Processor",
	})
	if len(inventory.Processors) != 0 || inventory.System == nil || inventory.Memory == nil || len(inventory.Disks) == 0 {
		t.Fatalf("query panic affected unrelated data: %#v", inventory)
	}
}

func TestDiscoverLiveWMI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live local-WMI smoke test in short mode")
	}
	inventory := Discover()
	if _, err := json.Marshal(inventory); err != nil {
		t.Fatalf("marshal live inventory: %v", err)
	}
	t.Logf("live inventory: system=%t memory=%t processors=%d disks=%d network_adapters=%d gpus=%d", inventory.System != nil, inventory.Memory != nil, len(inventory.Processors), len(inventory.Disks), len(inventory.NetworkAdapters), len(inventory.GPUs))
	if len(inventory.Disks) > 0 {
		disk := inventory.Disks[0]
		t.Logf("first live disk: physical_sector_bytes=%d media_type=%q bus_type=%q partition_table_type=%q partitions=%d", disk.PhysicalSectorSizeBytes, disk.MediaType, disk.BusType, disk.PartitionTableType, len(disk.Partitions))
	}
}

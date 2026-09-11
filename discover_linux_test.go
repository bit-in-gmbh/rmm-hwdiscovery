//go:build linux && (amd64 || arm64)

package hwdiscovery

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestLinuxCompleteInventoryAndDeterministicOrder(t *testing.T) {
	source := completeLinuxFixture(t)
	first := discoverLinux(source)
	second := discoverLinux(source)

	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first inventory: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second inventory: %v", err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("Linux discovery is not deterministic\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}

	if first.System == nil || first.System.Manufacturer != "Example Corp" || first.System.Model != "RoadRunner" || first.System.UUID != "abcdef12-3456-7890-abcd-ef1234567890" || first.System.SystemType == "" {
		t.Fatalf("unexpected system: %#v", first.System)
	}
	if first.System.Chassis == nil || first.System.Chassis.Type != "notebook" || first.System.Baseboard == nil || first.System.Firmware == nil || first.System.Firmware.ReleaseDate != "2026-04-03" {
		t.Fatalf("unexpected system components: %#v", first.System)
	}
	if len(first.Processors) != 1 || first.Processors[0].ID != "CPU0" || first.Processors[0].SerialNumber != "CPU-SERIAL" || first.Processors[0].PhysicalCoreCount != 2 || first.Processors[0].LogicalProcessorCount != 3 || first.Processors[0].MaxClockMHz != 4200 {
		t.Fatalf("unexpected processors: %#v", first.Processors)
	}
	if first.Memory == nil || first.Memory.InstalledPhysicalBytes != 8<<30 || len(first.Memory.Modules) != 2 || first.Memory.Modules[0].MemoryType != "ddr5" || first.Memory.Modules[1].RatedSpeedMTs != 5600 || first.Memory.Modules[1].ConfiguredSpeedMTs != 5200 {
		t.Fatalf("unexpected memory: %#v", first.Memory)
	}
	if len(first.Disks) != 1 || first.Disks[0].ID != "/dev/nvme0n1" || first.Disks[0].BusType != "nvme" || first.Disks[0].MediaType != "ssd" || first.Disks[0].PartitionTableType != "gpt" || len(first.Disks[0].Partitions) != 2 {
		t.Fatalf("unexpected disks: %#v", first.Disks)
	}
	firstPartition := first.Disks[0].Partitions[0]
	secondPartition := first.Disks[0].Partitions[1]
	if len(firstPartition.Volumes) != 1 || firstPartition.Volumes[0].ID != "BOOT-UUID" || firstPartition.Volumes[0].MountPoints[0] != "/boot efi" {
		t.Fatalf("unexpected direct volume: %#v", firstPartition)
	}
	if len(secondPartition.Volumes) != 1 || secondPartition.Volumes[0].ID != "ROOT-UUID" || secondPartition.Volumes[0].Filesystem != "ext4" || secondPartition.Volumes[0].MountPoints[0] != "/" {
		t.Fatalf("layered filesystem was not attached to its backing partition: %#v", secondPartition)
	}
	if len(first.NetworkAdapters) != 2 || first.NetworkAdapters[0].ID != "eth0" || first.NetworkAdapters[0].Vendor != "Network Vendor" || first.NetworkAdapters[0].Model != "Network Model" || first.NetworkAdapters[0].MACAddress != "00:11:22:33:44:55" || first.NetworkAdapters[0].PhysicalMedium != "ethernet" || first.NetworkAdapters[1].PhysicalMedium != "wireless_lan" || first.NetworkAdapters[1].MACAddress != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("unexpected network adapters: %#v", first.NetworkAdapters)
	}
	if len(first.GPUs) != 2 || first.GPUs[0].ID != "0000:02:00.0" || first.GPUs[0].Manufacturer != "Graphics Vendor" || first.GPUs[0].VideoProcessor != "Graphics Model" || first.GPUs[1].ID != "devices/platform/soc-gpu" || first.GPUs[1].VideoProcessor != "vendor,soc-gpu" {
		t.Fatalf("unexpected GPUs or failed deduplication: %#v", first.GPUs)
	}
}

func TestLinuxOptionalMetadataAndMalformedInputsAreIsolated(t *testing.T) {
	source := completeLinuxFixture(t)
	source.runRoot = filepath.Join(t.TempDir(), "missing-run")
	source.pciIDPaths = []string{filepath.Join(t.TempDir(), "missing-pci.ids")}

	inventory := discoverLinux(source)
	if inventory.System == nil || inventory.Memory == nil || len(inventory.Processors) != 1 || len(inventory.Disks) != 1 || len(inventory.Disks[0].Partitions) != 2 || len(inventory.NetworkAdapters) != 2 || len(inventory.GPUs) != 2 {
		t.Fatalf("optional metadata failure discarded base entities: %#v", inventory)
	}
	if inventory.Disks[0].PartitionTableType != "" {
		t.Fatalf("partition-table enrichment unexpectedly survived missing udev data: %#v", inventory.Disks[0])
	}

	badDMI := make([]byte, 8)
	badDMI[0], badDMI[1] = 17, 64
	writeFixture(t, filepath.Join(source.sysRoot, "firmware/dmi/entries/17-0/raw"), badDMI)
	if memory := collectLinuxMemory(source); memory == nil || memory.InstalledPhysicalBytes != 8<<30 || len(memory.Modules) != 1 {
		t.Fatalf("one malformed DMI record affected independent memory data: %#v", memory)
	}

	overflow := filepath.Join(t.TempDir(), "sectors")
	writeFixture(t, overflow, []byte("18446744073709551615\n"))
	if value, ok := linuxSectorBytes(overflow); ok || value != 0 {
		t.Fatalf("overflowing sector count was accepted: value=%d ok=%t", value, ok)
	}
}

func TestLinuxAssignedMACIsOmittedWithoutPermanentMetadata(t *testing.T) {
	source := completeLinuxFixture(t)
	writeFixture(t, source.sys("class/net/eth0/addr_assign_type"), []byte("3\n"))
	source.runRoot = filepath.Join(t.TempDir(), "missing-run")
	adapters := collectLinuxNetworkAdapters(source, loadPCIDatabase(source.pciIDPaths))
	if len(adapters) != 2 || adapters[0].ID != "eth0" || adapters[0].MACAddress != "" {
		t.Fatalf("assigned MAC was reported as permanent: %#v", adapters)
	}
}

func TestLinuxLayeredVolumeCanReachMultiplePhysicalPartitions(t *testing.T) {
	root := t.TempDir()
	mdPath := filepath.Join(root, "md0")
	writeFixture(t, filepath.Join(mdPath, "dev"), []byte("9:0\n"))
	linkFixture(t, filepath.Join(root, "p1"), filepath.Join(mdPath, "slaves/p1"))
	linkFixture(t, filepath.Join(root, "p2"), filepath.Join(mdPath, "slaves/p2"))
	blocks := map[string]linuxBlock{
		"md0": {name: "md0", path: mdPath, resolved: mdPath},
		"p1":  {name: "p1", path: filepath.Join(root, "p1"), resolved: filepath.Join(root, "p1")},
		"p2":  {name: "p2", path: filepath.Join(root, "p2"), resolved: filepath.Join(root, "p2")},
	}
	locations := map[string]linuxPartitionLocation{
		"p1": {disk: 0, partition: 0},
		"p2": {disk: 1, partition: 0},
	}
	backing := linuxBackingPartitions("md0", blocks, locations, make(map[string]bool))
	if len(backing) != 2 {
		t.Fatalf("expected both physical backing partitions, got %#v", backing)
	}
}

func TestLinuxMountInfoUnescape(t *testing.T) {
	if value := unescapeMountInfo(`/media/My\040Disk\134Path`); value != "/media/My Disk\\Path" {
		t.Fatalf("unexpected mountinfo unescape result: %q", value)
	}
}

func TestLinuxMountSourceFallbackForAnonymousFilesystemDevice(t *testing.T) {
	root := t.TempDir()
	source := linuxSource{procRoot: filepath.Join(root, "proc"), devRoot: filepath.Join(root, "dev")}
	writeFixture(t, source.proc("self/mountinfo"), []byte("1 0 0:42 / /data rw - btrfs "+filepath.Join(source.devRoot, "mapper/data")+" rw\n"))
	writeFixture(t, filepath.Join(source.devRoot, "dm-0"), nil)
	linkFixture(t, filepath.Join(source.devRoot, "dm-0"), filepath.Join(source.devRoot, "mapper/data"))
	blocks := map[string]linuxBlock{"dm-0": {name: "dm-0", dev: "253:0"}}
	mounts := readLinuxMounts(source, blocks)
	if mount := mounts["dm-0"]; len(mount.points) != 1 || mount.points[0] != "/data" || mount.filesystem != "btrfs" {
		t.Fatalf("mount source did not recover anonymous filesystem device: %#v", mounts)
	}
}

func TestDiscoverLiveLinux(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live Linux discovery in short mode")
	}
	inventory := Discover()
	if _, err := json.Marshal(inventory); err != nil {
		t.Fatalf("marshal live inventory: %v", err)
	}
	t.Logf("live inventory: system=%t memory=%t processors=%d disks=%d network_adapters=%d gpus=%d", inventory.System != nil, inventory.Memory != nil, len(inventory.Processors), len(inventory.Disks), len(inventory.NetworkAdapters), len(inventory.GPUs))
}

func completeLinuxFixture(t *testing.T) linuxSource {
	t.Helper()
	root := t.TempDir()
	source := linuxSource{
		sysRoot:    filepath.Join(root, "sys"),
		procRoot:   filepath.Join(root, "proc"),
		runRoot:    filepath.Join(root, "run"),
		devRoot:    "/dev",
		pciIDPaths: []string{filepath.Join(root, "pci.ids")},
	}

	dmi := source.sys("class/dmi/id")
	writeStrings(t, dmi, map[string]string{
		"sys_vendor": "Example Corp", "product_name": "RoadRunner", "product_family": "Mobile",
		"product_version": "Rev 2", "product_serial": "SYS-123", "product_uuid": "ABCDEF1234567890ABCDEF1234567890",
		"product_sku": "SKU-7", "chassis_vendor": "Example Corp", "chassis_version": "Shell",
		"chassis_serial": "CASE-1", "chassis_asset_tag": "ASSET-9", "chassis_type": "10",
		"board_vendor": "Boards Ltd", "board_name": "Board X", "board_version": "1.2", "board_serial": "BOARD-1",
		"bios_vendor": "Firmware Inc", "bios_version": "2.4.6", "bios_date": "04/03/2026",
	})

	processorRaw := dmiFixtureRecord(4, 48, []string{"SOCKET 0", "Chip Co", "FastChip", "CPU-SERIAL"}, func(formatted []byte) {
		formatted[4], formatted[5], formatted[7], formatted[16], formatted[24], formatted[32] = 1, 3, 2, 3, 0x41, 4
		binary.LittleEndian.PutUint16(formatted[20:22], 4100)
		formatted[35], formatted[37] = 2, 3
	})
	writeFixture(t, source.sys("firmware/dmi/entries/4-0/raw"), processorRaw)

	memoryA := dmiFixtureRecord(17, 40, []string{"DIMM_A", "BANK 0", "Memory Co", "MEM-A", "PART-A"}, func(formatted []byte) {
		binary.LittleEndian.PutUint16(formatted[12:14], 4096)
		formatted[14], formatted[16], formatted[17], formatted[18] = 12, 1, 2, 34
		binary.LittleEndian.PutUint16(formatted[21:23], 4800)
		formatted[23], formatted[24], formatted[26] = 3, 4, 5
		binary.LittleEndian.PutUint16(formatted[32:34], 4800)
	})
	memoryB := dmiFixtureRecord(17, 92, []string{"DIMM_B", "BANK 1", "Memory Co", "MEM-B", "PART-B"}, func(formatted []byte) {
		binary.LittleEndian.PutUint16(formatted[12:14], 0x7fff)
		formatted[14], formatted[16], formatted[17], formatted[18] = 8, 1, 2, 34
		binary.LittleEndian.PutUint16(formatted[21:23], math.MaxUint16)
		formatted[23], formatted[24], formatted[26] = 3, 4, 5
		binary.LittleEndian.PutUint32(formatted[28:32], 4096)
		binary.LittleEndian.PutUint16(formatted[32:34], math.MaxUint16)
		binary.LittleEndian.PutUint32(formatted[84:88], 5600)
		binary.LittleEndian.PutUint32(formatted[88:92], 5200)
	})
	writeFixture(t, source.sys("firmware/dmi/entries/17-0/raw"), memoryA)
	writeFixture(t, source.sys("firmware/dmi/entries/17-1/raw"), memoryB)
	emptyMemory := dmiFixtureRecord(17, 40, []string{"DIMM_C"}, func(formatted []byte) {
		formatted[14], formatted[16], formatted[18] = 8, 1, 34
	})
	writeFixture(t, source.sys("firmware/dmi/entries/17-2/raw"), emptyMemory)

	for cpu, core := range map[int]int{0: 0, 1: 0, 2: 1} {
		path := source.sys("devices/system/cpu", "cpu"+itoa(cpu))
		writeStrings(t, filepath.Join(path, "topology"), map[string]string{"physical_package_id": "0", "core_id": itoa(core), "die_id": "0"})
		writeFixture(t, filepath.Join(path, "cpufreq/cpuinfo_max_freq"), []byte("4200000\n"))
	}
	writeFixture(t, source.proc("cpuinfo"), []byte("processor: 0\nphysical id: 0\nvendor_id: Proc Vendor\nmodel name: Proc Model\ncpu MHz: 9999\n\nprocessor: 1\nphysical id: 0\nvendor_id: Proc Vendor\nmodel name: Proc Model\n\nprocessor: 2\nphysical id: 0\nvendor_id: Proc Vendor\nmodel name: Proc Model\n"))
	writeFixture(t, source.proc("meminfo"), []byte("MemTotal: 8388608 kB\nMemFree: 1 kB\n"))

	diskPath := source.sys("devices/pci0000:00/nvme/nvme0n1")
	partition1Path := filepath.Join(diskPath, "nvme0n1p1")
	partition2Path := filepath.Join(diskPath, "nvme0n1p2")
	writeStrings(t, diskPath, map[string]string{"dev": "259:0", "size": "2000000", "removable": "0"})
	writeStrings(t, filepath.Join(diskPath, "queue"), map[string]string{"logical_block_size": "512", "physical_block_size": "4096", "rotational": "0"})
	writeStrings(t, filepath.Join(diskPath, "device"), map[string]string{"vendor": "Disk Co", "model": "Speedy", "serial": "DISK-A", "uevent": "MODALIAS=pci:disk\n"})
	writeFixture(t, filepath.Join(diskPath, "uevent"), []byte("MAJOR=259\nMINOR=0\nDEVNAME=nvme0n1\nDEVTYPE=disk\n"))
	writeStrings(t, partition1Path, map[string]string{"dev": "259:1", "partition": "1", "start": "2048", "size": "400000", "uevent": "MAJOR=259\nMINOR=1\nDEVTYPE=partition\n"})
	writeStrings(t, partition2Path, map[string]string{"dev": "259:2", "partition": "2", "start": "402048", "size": "1597952", "uevent": "MAJOR=259\nMINOR=2\nDEVTYPE=partition\n"})
	linkFixture(t, diskPath, source.sys("class/block/nvme0n1"))
	linkFixture(t, partition1Path, source.sys("class/block/nvme0n1p1"))
	linkFixture(t, partition2Path, source.sys("class/block/nvme0n1p2"))

	dmPath := source.sys("devices/virtual/block/dm-0")
	writeStrings(t, dmPath, map[string]string{"dev": "253:0", "size": "1597000", "uevent": "MAJOR=253\nMINOR=0\nDEVTYPE=disk\n"})
	linkFixture(t, partition2Path, filepath.Join(dmPath, "slaves/nvme0n1p2"))
	linkFixture(t, dmPath, source.sys("class/block/dm-0"))

	writeFixture(t, source.run("udev/data/b259:0"), []byte("E:ID_PART_TABLE_TYPE=gpt\nE:ID_SERIAL_SHORT=DISK-A\n"))
	writeFixture(t, source.run("udev/data/b259:1"), []byte("E:ID_FS_USAGE=filesystem\nE:ID_FS_TYPE=vfat\nE:ID_FS_UUID=BOOT-UUID\nE:ID_FS_LABEL=Boot\nE:ID_FS_SIZE=204800000\n"))
	writeFixture(t, source.run("udev/data/b259:2"), []byte("E:ID_FS_USAGE=crypto\nE:ID_FS_TYPE=crypto_LUKS\nE:ID_FS_UUID=LUKS-UUID\n"))
	writeFixture(t, source.run("udev/data/b253:0"), []byte("E:ID_FS_USAGE=filesystem\nE:ID_FS_TYPE=ext4\nE:ID_FS_UUID=ROOT-UUID\nE:ID_FS_LABEL=Root\nE:ID_FS_SIZE=817664000\n"))
	writeFixture(t, source.proc("self/mountinfo"), []byte("1 0 253:0 / / rw - ext4 /dev/mapper/root rw\n2 1 259:1 / /boot\\040efi rw - vfat /dev/nvme0n1p1 rw\n3 1 0:99 / /proc rw - proc proc rw\n"))

	nicDevice := source.sys("devices/pci0000:00/0000:01:00.0")
	writeStrings(t, nicDevice, map[string]string{"vendor": "0x1234", "device": "0x5678", "uevent": "PCI_SLOT_NAME=0000:01:00.0\nMODALIAS=pci:nic\n"})
	writeStrings(t, source.sys("class/net/eth0"), map[string]string{"ifindex": "2", "type": "1", "address": "00:11:22:33:44:55", "addr_assign_type": "0", "uevent": "INTERFACE=eth0\n"})
	linkFixture(t, nicDevice, source.sys("class/net/eth0/device"))
	usbDevice := source.sys("devices/pci0000:00/usb1/1-1/1-1:1.0")
	writeStrings(t, usbDevice, map[string]string{"manufacturer": "USB Network Corp", "product": "Wireless Adapter", "uevent": "MODALIAS=usb:network\n"})
	writeStrings(t, source.sys("class/net/wlan0"), map[string]string{"ifindex": "3", "type": "1", "address": "02:00:00:00:00:01", "addr_assign_type": "3", "uevent": "DEVTYPE=wlan\n"})
	if err := os.MkdirAll(source.sys("class/net/wlan0/wireless"), 0o755); err != nil {
		t.Fatalf("create wireless fixture: %v", err)
	}
	linkFixture(t, usbDevice, source.sys("class/net/wlan0/device"))
	writeFixture(t, source.run("udev/data/n3"), []byte("E:ID_VENDOR_FROM_DATABASE=USB Network Corp\nE:ID_MODEL_FROM_DATABASE=Wireless Adapter\nE:ID_NET_NAME_MAC=wlxaabbccddeeff\n"))

	gpuDevice := source.sys("devices/pci0000:00/0000:02:00.0")
	writeStrings(t, gpuDevice, map[string]string{"vendor": "0xabcd", "device": "0xef01", "class": "0x030000", "uevent": "PCI_SLOT_NAME=0000:02:00.0\nMODALIAS=pci:gpu\n"})
	linkFixture(t, gpuDevice, source.sys("bus/pci/devices/0000:02:00.0"))
	linkFixture(t, gpuDevice, source.sys("class/drm/card0/device"))
	platformGPU := source.sys("devices/platform/soc-gpu")
	writeFixture(t, filepath.Join(platformGPU, "uevent"), []byte("MODALIAS=platform:soc-gpu\n"))
	writeFixture(t, filepath.Join(platformGPU, "of_node/compatible"), []byte("vendor,soc-gpu\x00"))
	linkFixture(t, platformGPU, source.sys("class/drm/card1/device"))

	writeFixture(t, source.pciIDPaths[0], []byte("1234  Network Vendor\n\t5678  Network Model\nabcd  Graphics Vendor\n\tef01  Graphics Model\n"))
	return source
}

func dmiFixtureRecord(recordType, length byte, values []string, populate func([]byte)) []byte {
	formatted := make([]byte, int(length))
	formatted[0], formatted[1] = recordType, length
	populate(formatted)
	result := append([]byte(nil), formatted...)
	for _, value := range values {
		result = append(result, []byte(value)...)
		result = append(result, 0)
	}
	return append(result, 0)
}

func writeStrings(t *testing.T, root string, values map[string]string) {
	t.Helper()
	for name, value := range values {
		writeFixture(t, filepath.Join(root, name), []byte(value+"\n"))
	}
}

func writeFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}

func linkFixture(t *testing.T, target, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture symlink directory for %s: %v", path, err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink fixture %s: %v", path, err)
	}
}

func itoa(value int) string {
	return strconv.Itoa(value)
}

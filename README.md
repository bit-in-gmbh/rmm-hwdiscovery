# bigrmm-hwdiscovery

`bigrmm-hwdiscovery` is a small, best-effort Go library for inventorying static hardware identity and configuration. Version 1 supports local Windows WMI over COM and never starts external programs.

## Usage

```go
package main

import (
	"encoding/json"
	"fmt"

	hwdiscovery "github.com/bit-in-gmbh/bigrmm-hwdiscovery"
)

func main() {
	inventory := hwdiscovery.Discover()
	encoded, _ := json.MarshalIndent(inventory, "", "  ")
	fmt.Println(string(encoded))
}
```

`Discover` has no configuration and returns no error. Queries are local, sequential, and independent. Missing WMI classes, unavailable properties, permissions failures, and unsupported enrichment are represented by omitted fields rather than errors.

The following example shows every possible JSON field. Actual results omit
zero-valued and unavailable data:

```json
{
  "system": {
    "manufacturer": "Example Corp",
    "model": "RoadRunner 15",
    "family": "Mobile",
    "version": "Rev 2",
    "serial_number": "SYS-123",
    "uuid": "abcdef12-3456-7890-abcd-ef1234567890",
    "sku": "SKU-7",
    "system_type": "x86_64",
    "chassis": {
      "manufacturer": "Example Corp",
      "model": "Shell",
      "serial_number": "CASE-1",
      "asset_tag": "ASSET-9",
      "type": "laptop"
    },
    "baseboard": {
      "manufacturer": "Boards Ltd",
      "product": "Board X",
      "version": "1.2",
      "serial_number": "BOARD-1"
    },
    "firmware": {
      "vendor": "Firmware Inc",
      "version": "2.4.6",
      "release_date": "2026-04-03"
    }
  },
  "memory": {
    "installed_physical_bytes": 34359738368,
    "modules": [
      {
        "bank": "BANK 0",
        "location": "DIMM_A",
        "vendor": "Memory Co",
        "part_number": "PART-A",
        "serial_number": "MEM-A",
        "capacity_bytes": 17179869184,
        "configured_speed_mts": 3200,
        "rated_speed_mts": 3200,
        "memory_type": "ddr4",
        "form_factor": "dimm"
      },
      {
        "bank": "BANK 1",
        "location": "DIMM_B",
        "vendor": "Memory Co",
        "part_number": "PART-B",
        "serial_number": "MEM-B",
        "capacity_bytes": 17179869184,
        "configured_speed_mts": 5200,
        "rated_speed_mts": 5600,
        "memory_type": "ddr5",
        "form_factor": "sodimm"
      }
    ]
  },
  "processors": [
    {
      "id": "CPU0",
      "manufacturer": "Chip Co",
      "model": "FastChip",
      "serial_number": "PROCESSOR-A",
      "architecture": "x86_64",
      "socket": "Socket A",
      "physical_core_count": 8,
      "logical_processor_count": 16,
      "max_clock_mhz": 4200
    },
    {
      "id": "CPU1",
      "manufacturer": "Chip Co",
      "model": "FastChip",
      "serial_number": "PROCESSOR-B",
      "architecture": "x86_64",
      "socket": "Socket B",
      "physical_core_count": 8,
      "logical_processor_count": 16,
      "max_clock_mhz": 4200
    }
  ],
  "disks": [
    {
      "id": "\\\\.\\PHYSICALDRIVE0",
      "index": 0,
      "pnp_id": "PCI\\DISK0",
      "vendor": "Disk Co",
      "model": "Speedy",
      "serial_number": "DISK-A",
      "capacity_bytes": 1000000,
      "logical_sector_size_bytes": 512,
      "physical_sector_size_bytes": 4096,
      "media_type": "ssd",
      "bus_type": "nvme",
      "partition_table_type": "gpt",
      "partitions": [
        {
          "id": "Disk #0, Partition #0",
          "index": 0,
          "size_bytes": 400000,
          "starting_offset_bytes": 1024,
          "volumes": [
            {
              "id": "C:",
              "label": "System",
              "filesystem": "ntfs",
              "capacity_bytes": 400000,
              "mount_points": ["C:\\"]
            }
          ]
        },
        {
          "id": "Disk #0, Partition #1",
          "index": 1,
          "size_bytes": 600000,
          "starting_offset_bytes": 400000,
          "volumes": [
            {
              "id": "D:",
              "label": "Data",
              "filesystem": "ntfs",
              "capacity_bytes": 600000,
              "mount_points": ["D:\\"]
            }
          ]
        }
      ]
    },
    {
      "id": "\\\\.\\PHYSICALDRIVE1",
      "index": 1,
      "pnp_id": "USBSTOR\\DISK1",
      "vendor": "Disk Co",
      "model": "Archive",
      "serial_number": "DISK-B",
      "capacity_bytes": 2000000,
      "logical_sector_size_bytes": 512,
      "physical_sector_size_bytes": 4096,
      "media_type": "hdd",
      "bus_type": "usb",
      "partition_table_type": "mbr",
      "partitions": [
        {
          "id": "Disk #1, Partition #0",
          "index": 0,
          "size_bytes": 2000000,
          "starting_offset_bytes": 1024,
          "volumes": [
            {
              "id": "E:",
              "label": "Archive",
              "filesystem": "exfat",
              "capacity_bytes": 2000000,
              "mount_points": ["E:\\"]
            }
          ]
        }
      ]
    }
  ],
  "network_adapters": [
    {
      "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "name": "Ethernet",
      "model": "Ether 1",
      "vendor": "Net Co",
      "physical_medium": "ethernet",
      "mac_address": "00:11:22:33:44:55",
      "pnp_id": "PCI\\NIC-A"
    },
    {
      "id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "name": "Wi-Fi",
      "model": "Wireless 2",
      "vendor": "Net Co",
      "physical_medium": "wireless_lan",
      "mac_address": "00:11:22:AA:BB:CC",
      "pnp_id": "PCI\\NIC-B"
    }
  ],
  "gpus": [
    {
      "id": "PCI\\GPU-A",
      "pnp_id": "PCI\\GPU-A",
      "name": "GPU A",
      "manufacturer": "Graphics Co",
      "video_processor": "Core A"
    },
    {
      "id": "PCI\\GPU-B",
      "pnp_id": "PCI\\GPU-B",
      "name": "GPU B",
      "manufacturer": "Graphics Co",
      "video_processor": "Core B"
    }
  ]
}
```

Byte fields are exact byte counts. Memory speeds are MT/s, maximum processor clocks are MHz, firmware dates use `YYYY-MM-DD`, UUIDs are lowercase, MAC addresses are uppercase colon-separated octets, and normalized enum strings are lowercase. All component collections are sorted deterministically. Zero-valued and unavailable data is omitted from JSON.

## Platform support

| Platform | Architecture | Behavior |
| --- | --- | --- |
| Windows 10/11 | amd64, arm64 | Local WMI hardware discovery |
| Windows Server 2016+ | amd64, arm64 | Local WMI hardware discovery |
| Windows | 386 and other architectures | Compiles; returns an empty inventory |
| Linux | all Go-supported architectures | Compiles; returns an empty inventory |
| macOS | all Go-supported architectures | Compiles; returns an empty inventory |

No elevation is attempted. Hardware that the current process cannot inspect is omitted. Optional `MSFT_Disk` and `MSFT_PhysicalDisk` data enriches physical disks when the Storage namespace is available; base disks and partitions remain present when it is not.

## Inventory, not monitoring

This module collects hardware identity and configuration. It deliberately does not collect CPU load or current clock, available memory, disk free/used capacity or SMART health, network addresses/link state/current speed, GPU utilization or temperature, power-on hours, or other transient metrics. Runtime code does not invoke PowerShell, `wmic`, shells, or platform utilities.

## Security and privacy

Inventory may contain serial numbers, UUIDs, MAC addresses, PnP identifiers, asset tags, and volume identifiers. These values can identify or correlate a device. Treat serialized inventory as sensitive operational data: minimize retention, restrict access, encrypt it in transit and at rest, and obtain any consent required by your policies or applicable law.

## License and third-party notices

The project is licensed under Apache-2.0. Dependency and design-reference notices are in [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).

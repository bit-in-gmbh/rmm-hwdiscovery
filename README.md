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

An abbreviated result looks like this:

```json
{
  "system": {
    "manufacturer": "Example Corp",
    "model": "RoadRunner 15",
    "uuid": "abcdef12-3456-7890-abcd-ef1234567890",
    "system_type": "x86_64",
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
        "location": "DIMM_A",
        "capacity_bytes": 17179869184,
        "configured_speed_mts": 3200,
        "memory_type": "ddr4"
      }
    ]
  },
  "processors": [
    {
      "id": "CPU0",
      "architecture": "x86_64",
      "physical_core_count": 8,
      "logical_processor_count": 16,
      "max_clock_mhz": 4200
    }
  ],
  "disks": [
    {
      "id": "\\\\.\\PHYSICALDRIVE0",
      "index": 0,
      "capacity_bytes": 1000000,
      "logical_sector_size_bytes": 512,
      "physical_sector_size_bytes": 4096,
      "media_type": "ssd",
      "bus_type": "nvme",
      "partition_table_type": "gpt"
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

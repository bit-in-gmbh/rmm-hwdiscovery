package hwdiscovery

import (
	"encoding/json"
	"testing"
)

func TestJSONContract(t *testing.T) {
	zero := uint32(0)
	inventory := Inventory{
		System: &System{Manufacturer: "Acme"},
		Memory: &Memory{InstalledPhysicalBytes: 16},
		Processors: []Processor{{
			ID:          "CPU0",
			MaxClockMHz: 1,
		}},
		Disks: []Disk{{
			ID:            "disk0",
			Index:         &zero,
			CapacityBytes: 2,
		}},
		NetworkAdapters: []NetworkAdapter{{
			ID:         "nic0",
			MACAddress: "AA:BB:CC:DD:EE:FF",
		}},
		GPUs: []GPU{{ID: "gpu0"}},
	}

	encoded, err := json.Marshal(inventory)
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	const expected = `{"system":{"manufacturer":"Acme"},"memory":{"installed_physical_bytes":16},"processors":[{"id":"CPU0","max_clock_mhz":1}],"disks":[{"id":"disk0","index":0,"capacity_bytes":2}],"network_adapters":[{"id":"nic0","mac_address":"AA:BB:CC:DD:EE:FF"}],"gpus":[{"id":"gpu0"}]}`
	if string(encoded) != expected {
		t.Fatalf("unexpected JSON contract\nwant: %s\n got: %s", expected, encoded)
	}
}

func TestEmptyInventoryJSON(t *testing.T) {
	encoded, err := json.Marshal(Inventory{})
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	if string(encoded) != `{}` {
		t.Fatalf("empty inventory encoded as %s", encoded)
	}
}

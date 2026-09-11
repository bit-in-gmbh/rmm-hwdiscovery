package hwdiscovery

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestJSONContract(t *testing.T) {
	zero := uint32(0)
	inventory := Inventory{
		System: &System{Manufacturer: "Acme"},
		Memory: &Memory{
			InstalledPhysicalBytes: 16,
			Modules:                []MemoryModule{{SerialNumber: "memory-1"}},
		},
		Processors: []Processor{{
			ID:           "CPU0",
			SerialNumber: "processor-1",
			MaxClockMHz:  1,
		}},
		Disks: []Disk{{
			ID:            "disk0",
			Index:         &zero,
			SerialNumber:  "disk-1",
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
	const expected = `{"system":{"manufacturer":"Acme"},"memory":{"installed_physical_bytes":16,"modules":[{"serial_number":"memory-1"}]},"processors":[{"id":"CPU0","serial_number":"processor-1","max_clock_mhz":1}],"disks":[{"id":"disk0","index":0,"serial_number":"disk-1","capacity_bytes":2}],"network_adapters":[{"id":"nic0","mac_address":"AA:BB:CC:DD:EE:FF"}],"gpus":[{"id":"gpu0"}]}`
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

func TestREADMEContainsCompleteInventoryExample(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	golden, err := os.ReadFile("testdata/complete_inventory.json")
	if err != nil {
		t.Fatalf("read complete-inventory golden file: %v", err)
	}

	const marker = "```json"
	start := strings.Index(string(readme), marker)
	if start < 0 {
		t.Fatal("README does not contain a JSON example")
	}
	start += len(marker)
	end := strings.Index(string(readme[start:]), "```")
	if end < 0 {
		t.Fatal("README JSON example is not terminated")
	}
	example := []byte(strings.TrimSpace(string(readme[start : start+end])))

	var compactExample, compactGolden bytes.Buffer
	if err := json.Compact(&compactExample, example); err != nil {
		t.Fatalf("compact README JSON example: %v", err)
	}
	if err := json.Compact(&compactGolden, golden); err != nil {
		t.Fatalf("compact complete-inventory golden file: %v", err)
	}
	if !bytes.Equal(compactExample.Bytes(), compactGolden.Bytes()) {
		t.Fatal("README JSON example does not match the complete inventory fixture")
	}
}

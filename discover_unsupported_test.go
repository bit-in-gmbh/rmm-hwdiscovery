//go:build !windows || (!amd64 && !arm64)

package hwdiscovery

import (
	"reflect"
	"testing"
)

func TestDiscoverReturnsEmptyInventory(t *testing.T) {
	if inventory := Discover(); !reflect.DeepEqual(inventory, Inventory{}) {
		t.Fatalf("unsupported platform returned inventory: %#v", inventory)
	}
}

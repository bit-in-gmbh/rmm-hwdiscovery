//go:build darwin && !cgo

package hwdiscovery

func readDarwinNativeInventory() darwinNativeInventory {
	return darwinNativeInventory{}
}

//go:build (!windows && !linux) || (windows && !amd64 && !arm64) || (linux && !amd64 && !arm64)

package hwdiscovery

// Discover returns an empty inventory on unsupported platforms.
func Discover() Inventory {
	return Inventory{}
}

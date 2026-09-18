//go:build linux && (amd64 || arm64)

package hwdiscovery

// Discover returns a best-effort inventory of static hardware identity and
// configuration exposed by Linux kernel filesystems and optional local metadata
// caches. Inaccessible or malformed data is omitted.
func Discover() Inventory {
	return discoverLinux(defaultLinuxSource())
}

func discoverLinux(source linuxSource) Inventory {
	pci := loadPCIDatabase(source.pciIDPaths)
	return Inventory{
		System:          collectLinuxSystem(source),
		Memory:          collectLinuxMemory(source),
		Processors:      collectLinuxProcessors(source),
		Disks:           collectLinuxDisks(source),
		NetworkAdapters: collectLinuxNetworkAdapters(source, pci),
		GPUs:            collectLinuxGPUs(source, pci),
	}
}

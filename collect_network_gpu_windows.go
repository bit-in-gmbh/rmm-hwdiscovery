//go:build windows && (amd64 || arm64)

package hwdiscovery

import (
	"sort"
)

type win32NetworkAdapter struct {
	GUID            *string
	DeviceID        *string
	PNPDeviceID     *string
	Name            *string
	ProductName     *string
	Manufacturer    *string
	MACAddress      *string
	PhysicalAdapter *bool
	AdapterTypeID   *uint16
}

type win32VideoController struct {
	DeviceID             *string
	PNPDeviceID          *string
	Name                 *string
	AdapterCompatibility *string
	VideoProcessor       *string
}

func collectNetworkAdapters(q queryer) []NetworkAdapter {
	var rows []win32NetworkAdapter
	if queryClass(q, cimv2Namespace, "Win32_NetworkAdapter", &rows) != nil {
		return nil
	}
	adapters := make([]NetworkAdapter, 0, len(rows))
	for _, row := range rows {
		if row.PhysicalAdapter == nil || !*row.PhysicalAdapter {
			continue
		}
		guid := normalizeUUID(cleanStringPtr(row.GUID))
		adapter := NetworkAdapter{
			ID:             firstString(guid, cleanStringPtr(row.PNPDeviceID), cleanStringPtr(row.DeviceID)),
			Name:           cleanStringPtr(row.Name),
			Model:          cleanStringPtr(row.ProductName),
			Vendor:         cleanStringPtr(row.Manufacturer),
			PhysicalMedium: normalizePhysicalMedium(row.AdapterTypeID),
			MACAddress:     normalizeMAC(cleanStringPtr(row.MACAddress)),
			PNPID:          cleanStringPtr(row.PNPDeviceID),
		}
		if adapter.ID == "" {
			continue
		}
		adapters = append(adapters, adapter)
	}
	sort.Slice(adapters, func(i, j int) bool { return adapters[i].ID < adapters[j].ID })
	return adapters
}

func collectGPUs(q queryer) []GPU {
	var rows []win32VideoController
	if queryClass(q, cimv2Namespace, "Win32_VideoController", &rows) != nil {
		return nil
	}
	gpus := make([]GPU, 0, len(rows))
	for _, row := range rows {
		pnpID := cleanStringPtr(row.PNPDeviceID)
		gpu := GPU{
			ID:             firstString(pnpID, cleanStringPtr(row.DeviceID)),
			PNPID:          pnpID,
			Name:           cleanStringPtr(row.Name),
			Manufacturer:   cleanStringPtr(row.AdapterCompatibility),
			VideoProcessor: cleanStringPtr(row.VideoProcessor),
		}
		if gpu.ID == "" {
			continue
		}
		gpus = append(gpus, gpu)
	}
	sort.Slice(gpus, func(i, j int) bool { return gpus[i].ID < gpus[j].ID })
	return gpus
}

func normalizePhysicalMedium(adapterType *uint16) string {
	if adapterType == nil {
		return ""
	}
	media := map[uint16]string{
		0: "ethernet", 1: "token_ring", 2: "fddi", 3: "wan", 4: "localtalk",
		5: "ethernet", 6: "arcnet", 7: "arcnet", 8: "atm", 9: "wireless_lan",
		10: "infrared", 11: "bpc", 12: "co_wan", 13: "ieee_1394",
	}
	return media[*adapterType]
}

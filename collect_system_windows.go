//go:build windows && (amd64 || arm64)

package hwdiscovery

import "time"

type win32ComputerSystem struct {
	Manufacturer        *string
	Model               *string
	SystemFamily        *string
	SystemType          *string
	TotalPhysicalMemory *uint64
}

type win32ComputerSystemProduct struct {
	Vendor            *string
	Name              *string
	Version           *string
	IdentifyingNumber *string
	UUID              *string
	SKUNumber         *string
}

type win32SystemEnclosure struct {
	Manufacturer   *string
	Model          *string
	SerialNumber   *string
	SMBIOSAssetTag *string
	ChassisTypes   []int32
}

type win32BaseBoard struct {
	Manufacturer *string
	Product      *string
	Version      *string
	SerialNumber *string
}

type win32BIOS struct {
	Manufacturer      *string
	SMBIOSBIOSVersion *string
	ReleaseDate       *time.Time
}

func collectSystem(q queryer) (*System, uint64) {
	var system System
	var installedPhysicalBytes uint64

	var computerSystems []win32ComputerSystem
	if queryClass(q, cimv2Namespace, "Win32_ComputerSystem", &computerSystems) == nil && len(computerSystems) > 0 {
		row := computerSystems[0]
		system.Manufacturer = cleanStringPtr(row.Manufacturer)
		system.Model = cleanStringPtr(row.Model)
		system.Family = cleanStringPtr(row.SystemFamily)
		system.SystemType = normalizeSystemType(cleanStringPtr(row.SystemType))
		if row.TotalPhysicalMemory != nil {
			installedPhysicalBytes = *row.TotalPhysicalMemory
		}
	}

	var products []win32ComputerSystemProduct
	if queryClass(q, cimv2Namespace, "Win32_ComputerSystemProduct", &products) == nil && len(products) > 0 {
		row := products[0]
		system.Manufacturer = firstString(system.Manufacturer, cleanStringPtr(row.Vendor))
		system.Model = firstString(system.Model, cleanStringPtr(row.Name))
		system.Version = cleanStringPtr(row.Version)
		system.SerialNumber = cleanStringPtr(row.IdentifyingNumber)
		system.UUID = normalizeUUID(cleanStringPtr(row.UUID))
		system.SKU = cleanStringPtr(row.SKUNumber)
	}

	var enclosures []win32SystemEnclosure
	if queryClass(q, cimv2Namespace, "Win32_SystemEnclosure", &enclosures) == nil && len(enclosures) > 0 {
		row := enclosures[0]
		chassis := &Chassis{
			Manufacturer: cleanStringPtr(row.Manufacturer),
			Model:        cleanStringPtr(row.Model),
			SerialNumber: cleanStringPtr(row.SerialNumber),
			AssetTag:     cleanStringPtr(row.SMBIOSAssetTag),
			Type:         normalizeChassisType(row.ChassisTypes),
		}
		if *chassis != (Chassis{}) {
			system.Chassis = chassis
		}
	}

	var baseboards []win32BaseBoard
	if queryClass(q, cimv2Namespace, "Win32_BaseBoard", &baseboards) == nil && len(baseboards) > 0 {
		row := baseboards[0]
		baseboard := &Baseboard{
			Manufacturer: cleanStringPtr(row.Manufacturer),
			Product:      cleanStringPtr(row.Product),
			Version:      cleanStringPtr(row.Version),
			SerialNumber: cleanStringPtr(row.SerialNumber),
		}
		if *baseboard != (Baseboard{}) {
			system.Baseboard = baseboard
		}
	}

	var biosRows []win32BIOS
	if queryClass(q, cimv2Namespace, "Win32_BIOS", &biosRows) == nil && len(biosRows) > 0 {
		row := biosRows[0]
		firmware := &Firmware{
			Vendor:  cleanStringPtr(row.Manufacturer),
			Version: cleanStringPtr(row.SMBIOSBIOSVersion),
		}
		if row.ReleaseDate != nil && !row.ReleaseDate.IsZero() {
			firmware.ReleaseDate = row.ReleaseDate.Format("2006-01-02")
		}
		if *firmware != (Firmware{}) {
			system.Firmware = firmware
		}
	}

	if system == (System{}) {
		return nil, installedPhysicalBytes
	}
	return &system, installedPhysicalBytes
}

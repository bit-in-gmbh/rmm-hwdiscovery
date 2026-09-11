//go:build windows && (amd64 || arm64)

package hwdiscovery

import (
	"sort"
	"strconv"
	"strings"
)

const storageNamespace = `root\Microsoft\Windows\Storage`

type win32DiskDrive struct {
	DeviceID       *string
	Index          *uint32
	PNPDeviceID    *string
	Manufacturer   *string
	Model          *string
	SerialNumber   *string
	Size           *uint64
	BytesPerSector *uint32
	MediaType      *string
	InterfaceType  *string
}

type win32DiskPartition struct {
	DeviceID       *string
	DiskIndex      *uint32
	Index          *uint32
	Size           *uint64
	StartingOffset *uint64
	Type           *string
}

type win32LogicalDiskToPartition struct {
	Antecedent *string
	Dependent  *string
}

type win32LogicalDisk struct {
	DeviceID   *string
	VolumeName *string
	FileSystem *string
	Size       *uint64
}

type msftDisk struct {
	Number             *uint32
	UniqueId           *string
	FriendlyName       *string
	Manufacturer       *string
	Model              *string
	SerialNumber       *string
	Size               *uint64
	LogicalSectorSize  *uint32
	PhysicalSectorSize *uint32
	BusType            *uint16
	PartitionStyle     *uint16
}

type msftPhysicalDisk struct {
	DeviceId           *string
	FriendlyName       *string
	Manufacturer       *string
	Model              *string
	SerialNumber       *string
	Size               *uint64
	LogicalSectorSize  *uint32
	PhysicalSectorSize *uint32
	MediaType          *uint16
	BusType            *uint16
}

func collectDisks(q queryer) []Disk {
	var diskRows []win32DiskDrive
	if queryClass(q, cimv2Namespace, "Win32_DiskDrive", &diskRows) != nil {
		return nil
	}

	disks := make([]Disk, 0, len(diskRows))
	for _, row := range diskRows {
		disk := Disk{
			ID:           cleanStringPtr(row.DeviceID),
			Index:        cloneUint32(row.Index),
			PNPID:        cleanStringPtr(row.PNPDeviceID),
			Vendor:       cleanStringPtr(row.Manufacturer),
			Model:        cleanStringPtr(row.Model),
			SerialNumber: cleanStringPtr(row.SerialNumber),
			MediaType:    normalizeDiskMediaString(cleanStringPtr(row.MediaType)),
			BusType:      normalizeBusString(cleanStringPtr(row.InterfaceType)),
		}
		if row.Size != nil {
			disk.CapacityBytes = *row.Size
		}
		if row.BytesPerSector != nil {
			disk.LogicalSectorSizeBytes = *row.BytesPerSector
		}
		if disk.ID == "" && disk.Index == nil {
			continue
		}
		disks = append(disks, disk)
	}

	attachPartitions(q, disks)
	enrichMSFTDisks(q, disks)
	enrichMSFTPhysicalDisks(q, disks)

	for index := range disks {
		sortPartitions(disks[index].Partitions)
	}
	sort.Slice(disks, func(i, j int) bool {
		left, right := disks[i], disks[j]
		if left.Index != nil && right.Index != nil && *left.Index != *right.Index {
			return *left.Index < *right.Index
		}
		if left.Index != nil && right.Index == nil {
			return true
		}
		if left.Index == nil && right.Index != nil {
			return false
		}
		return left.ID < right.ID
	})
	return disks
}

func attachPartitions(q queryer, disks []Disk) {
	byDiskIndex := make(map[uint32]*Disk, len(disks))
	for index := range disks {
		if disks[index].Index != nil {
			byDiskIndex[*disks[index].Index] = &disks[index]
		}
	}

	var partitionRows []win32DiskPartition
	partitionsAvailable := queryClass(q, cimv2Namespace, "Win32_DiskPartition", &partitionRows) == nil
	if partitionsAvailable {
		for _, row := range partitionRows {
			if row.DiskIndex == nil {
				continue
			}
			disk := byDiskIndex[*row.DiskIndex]
			if disk == nil {
				continue
			}
			partition := Partition{
				ID:    cleanStringPtr(row.DeviceID),
				Index: cloneUint32(row.Index),
			}
			if row.Size != nil {
				partition.SizeBytes = *row.Size
			}
			if row.StartingOffset != nil {
				partition.StartingOffsetBytes = *row.StartingOffset
			}
			if partition.ID == "" && partition.Index == nil {
				continue
			}
			disk.Partitions = append(disk.Partitions, partition)
			if disk.PartitionTableType == "" {
				disk.PartitionTableType = inferPartitionStyle(cleanStringPtr(row.Type))
			}
		}
	}
	partitionByID := make(map[string]*Partition)
	for diskIndex := range disks {
		for partitionIndex := range disks[diskIndex].Partitions {
			partition := &disks[diskIndex].Partitions[partitionIndex]
			if partition.ID != "" {
				partitionByID[strings.ToLower(partition.ID)] = partition
			}
		}
	}

	var associationRows []win32LogicalDiskToPartition
	associationsAvailable := queryClass(q, cimv2Namespace, "Win32_LogicalDiskToPartition", &associationRows) == nil
	var logicalRows []win32LogicalDisk
	logicalDisksAvailable := queryClass(q, cimv2Namespace, "Win32_LogicalDisk", &logicalRows) == nil
	if !partitionsAvailable || !associationsAvailable || !logicalDisksAvailable {
		return
	}

	volumes := make(map[string]Volume, len(logicalRows))
	for _, row := range logicalRows {
		id := normalizeVolumeID(cleanStringPtr(row.DeviceID))
		if id == "" {
			continue
		}
		volume := Volume{
			ID:          id,
			Label:       cleanStringPtr(row.VolumeName),
			Filesystem:  strings.ToLower(cleanStringPtr(row.FileSystem)),
			MountPoints: []string{volumeMountPoint(id)},
		}
		if row.Size != nil {
			volume.CapacityBytes = *row.Size
		}
		volumes[strings.ToLower(id)] = volume
	}

	for _, row := range associationRows {
		partitionID := associationDeviceID(cleanStringPtr(row.Antecedent), "Win32_DiskPartition")
		volumeID := normalizeVolumeID(associationDeviceID(cleanStringPtr(row.Dependent), "Win32_LogicalDisk"))
		partition := partitionByID[strings.ToLower(partitionID)]
		volume, found := volumes[strings.ToLower(volumeID)]
		if partition == nil || !found {
			continue
		}
		partition.Volumes = append(partition.Volumes, volume)
	}
}

func enrichMSFTDisks(q queryer, disks []Disk) {
	var rows []msftDisk
	if queryClass(q, storageNamespace, "MSFT_Disk", &rows) != nil {
		return
	}
	byIndex := disksByIndex(disks)
	for _, row := range rows {
		if row.Number == nil || byIndex[*row.Number] == nil {
			continue
		}
		disk := byIndex[*row.Number]
		disk.ID = firstString(disk.ID, cleanStringPtr(row.UniqueId))
		disk.Vendor = firstString(disk.Vendor, cleanStringPtr(row.Manufacturer))
		disk.Model = firstString(disk.Model, cleanStringPtr(row.Model), cleanStringPtr(row.FriendlyName))
		disk.SerialNumber = firstString(disk.SerialNumber, cleanStringPtr(row.SerialNumber))
		if row.Size != nil && disk.CapacityBytes == 0 {
			disk.CapacityBytes = *row.Size
		}
		if row.LogicalSectorSize != nil {
			disk.LogicalSectorSizeBytes = *row.LogicalSectorSize
		}
		if row.PhysicalSectorSize != nil {
			disk.PhysicalSectorSizeBytes = *row.PhysicalSectorSize
		}
		if busType := normalizeBusType(row.BusType); busType != "" {
			disk.BusType = busType
		}
		if partitionStyle := normalizePartitionStyle(row.PartitionStyle); partitionStyle != "" {
			disk.PartitionTableType = partitionStyle
		}
	}
}

func enrichMSFTPhysicalDisks(q queryer, disks []Disk) {
	var rows []msftPhysicalDisk
	if queryClass(q, storageNamespace, "MSFT_PhysicalDisk", &rows) != nil {
		return
	}
	byIndex := disksByIndex(disks)
	for _, row := range rows {
		disk := diskForPhysicalRow(row, disks, byIndex)
		if disk == nil {
			continue
		}
		disk.Vendor = firstString(disk.Vendor, cleanStringPtr(row.Manufacturer))
		disk.Model = firstString(disk.Model, cleanStringPtr(row.Model), cleanStringPtr(row.FriendlyName))
		disk.SerialNumber = firstString(disk.SerialNumber, cleanStringPtr(row.SerialNumber))
		if row.Size != nil && disk.CapacityBytes == 0 {
			disk.CapacityBytes = *row.Size
		}
		if row.LogicalSectorSize != nil {
			disk.LogicalSectorSizeBytes = *row.LogicalSectorSize
		}
		if row.PhysicalSectorSize != nil {
			disk.PhysicalSectorSizeBytes = *row.PhysicalSectorSize
		}
		if mediaType := normalizeDiskMediaType(row.MediaType); mediaType != "" {
			disk.MediaType = mediaType
		}
		if busType := normalizeBusType(row.BusType); busType != "" {
			disk.BusType = busType
		}
	}
}

func disksByIndex(disks []Disk) map[uint32]*Disk {
	result := make(map[uint32]*Disk, len(disks))
	for index := range disks {
		if disks[index].Index != nil {
			result[*disks[index].Index] = &disks[index]
		}
	}
	return result
}

func diskForPhysicalRow(row msftPhysicalDisk, disks []Disk, byIndex map[uint32]*Disk) *Disk {
	if deviceID := cleanStringPtr(row.DeviceId); deviceID != "" {
		if index, err := strconv.ParseUint(deviceID, 10, 32); err == nil {
			if disk := byIndex[uint32(index)]; disk != nil {
				return disk
			}
		}
	}
	serial := cleanStringPtr(row.SerialNumber)
	if serial != "" {
		for index := range disks {
			if strings.EqualFold(disks[index].SerialNumber, serial) {
				return &disks[index]
			}
		}
	}
	return nil
}

func sortPartitions(partitions []Partition) {
	for index := range partitions {
		sort.Slice(partitions[index].Volumes, func(i, j int) bool {
			return partitions[index].Volumes[i].ID < partitions[index].Volumes[j].ID
		})
	}
	sort.Slice(partitions, func(i, j int) bool {
		left, right := partitions[i], partitions[j]
		if left.Index != nil && right.Index != nil && *left.Index != *right.Index {
			return *left.Index < *right.Index
		}
		if left.Index != nil && right.Index == nil {
			return true
		}
		if left.Index == nil && right.Index != nil {
			return false
		}
		return left.ID < right.ID
	})
}

func cloneUint32(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

//go:build darwin

package hwdiscovery

import (
	"encoding/binary"
	"math"
	"sort"
)

type darwinSMBIOSRecord struct {
	formatted []byte
	strings   []string
}

func parseDarwinSMBIOSMemory(data []byte) []MemoryModule {
	records := parseDarwinSMBIOS(data)
	modules := make([]MemoryModule, 0)
	for _, record := range records {
		if len(record.formatted) < 19 || record.formatted[0] != 17 {
			continue
		}
		capacity, installed := darwinSMBIOSMemoryCapacity(record)
		if !installed {
			continue
		}
		module := MemoryModule{
			Bank:               record.stringAt(17),
			Location:           record.stringAt(16),
			Vendor:             record.stringAt(23),
			PartNumber:         record.stringAt(26),
			SerialNumber:       record.stringAt(24),
			CapacityBytes:      capacity,
			ConfiguredSpeedMTs: darwinSMBIOSSpeed(record, 32, 88),
			RatedSpeedMTs:      darwinSMBIOSSpeed(record, 21, 84),
			MemoryType:         smbiosMemoryType(uint32(record.formatted[18])),
		}
		if len(record.formatted) > 14 {
			module.FormFactor = memoryFormFactor(uint16(record.formatted[14]))
		}
		modules = append(modules, module)
	}
	sort.Slice(modules, func(i, j int) bool {
		left, right := modules[i], modules[j]
		if left.Location != right.Location {
			return left.Location < right.Location
		}
		if left.Bank != right.Bank {
			return left.Bank < right.Bank
		}
		if left.SerialNumber != right.SerialNumber {
			return left.SerialNumber < right.SerialNumber
		}
		return left.PartNumber < right.PartNumber
	})
	return modules
}

func parseDarwinSMBIOS(data []byte) []darwinSMBIOSRecord {
	if len(data) < 6 {
		return nil
	}
	candidates := []int{0}
	scanLimit := len(data)
	if scanLimit > 64*1024 {
		scanLimit = 64 * 1024
	}
	for offset := 1; offset+4 <= scanLimit && len(candidates) < 64; offset++ {
		if data[offset] == 0 && data[offset+1] >= 0x12 && int(data[offset+1]) <= len(data)-offset {
			candidates = append(candidates, offset)
		}
	}
	var best []darwinSMBIOSRecord
	for _, start := range candidates {
		records := parseDarwinSMBIOSTable(data[start:])
		if len(records) > len(best) {
			best = records
		}
	}
	return best
}

func parseDarwinSMBIOSTable(data []byte) []darwinSMBIOSRecord {
	records := make([]darwinSMBIOSRecord, 0)
	for offset := 0; offset+4 <= len(data); {
		length := int(data[offset+1])
		if length < 4 || offset+length > len(data) {
			return nil
		}
		stringsEnd := offset + length
		for stringsEnd+1 < len(data) && !(data[stringsEnd] == 0 && data[stringsEnd+1] == 0) {
			stringsEnd++
		}
		if stringsEnd+1 >= len(data) {
			return nil
		}
		record := darwinSMBIOSRecord{formatted: data[offset : offset+length]}
		for stringOffset := offset + length; stringOffset < stringsEnd; {
			end := stringOffset
			for end < stringsEnd && data[end] != 0 {
				end++
			}
			record.strings = append(record.strings, cleanString(string(data[stringOffset:end])))
			stringOffset = end + 1
		}
		records = append(records, record)
		offset = stringsEnd + 2
		if record.formatted[0] == 127 {
			return records
		}
	}
	return records
}

func (record darwinSMBIOSRecord) stringAt(offset int) string {
	if offset >= len(record.formatted) {
		return ""
	}
	index := int(record.formatted[offset])
	if index == 0 || index > len(record.strings) {
		return ""
	}
	return record.strings[index-1]
}

func (record darwinSMBIOSRecord) uint16At(offset int) uint16 {
	if offset < 0 || offset+2 > len(record.formatted) {
		return 0
	}
	return binary.LittleEndian.Uint16(record.formatted[offset : offset+2])
}

func (record darwinSMBIOSRecord) uint32At(offset int) uint32 {
	if offset < 0 || offset+4 > len(record.formatted) {
		return 0
	}
	return binary.LittleEndian.Uint32(record.formatted[offset : offset+4])
}

func darwinSMBIOSMemoryCapacity(record darwinSMBIOSRecord) (uint64, bool) {
	size := record.uint16At(12)
	switch size {
	case 0, 0xffff:
		return 0, false
	case 0x7fff:
		extended := uint64(record.uint32At(28) & 0x7fffffff)
		if extended == 0 || extended > math.MaxUint64/(1024*1024) {
			return 0, false
		}
		return extended * 1024 * 1024, true
	default:
		units := uint64(1024 * 1024)
		if size&0x8000 != 0 {
			units = 1024
			size &= 0x7fff
		}
		return uint64(size) * units, size != 0
	}
}

func darwinSMBIOSSpeed(record darwinSMBIOSRecord, wordOffset, extendedOffset int) uint32 {
	speed := record.uint16At(wordOffset)
	if speed == math.MaxUint16 {
		return record.uint32At(extendedOffset)
	}
	return uint32(speed)
}

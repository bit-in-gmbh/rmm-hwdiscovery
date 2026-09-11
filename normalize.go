package hwdiscovery

import (
	"net"
	"strings"
)

var firmwarePlaceholders = map[string]struct{}{
	"0123456789":             {},
	"123456789":              {},
	"default string":         {},
	"invalid":                {},
	"n/a":                    {},
	"na":                     {},
	"none":                   {},
	"not applicable":         {},
	"not specified":          {},
	"o.e.m.":                 {},
	"oem":                    {},
	"system manufacturer":    {},
	"system product name":    {},
	"system serial number":   {},
	"to be filled by o.e.m.": {},
	"to be filled by oem":    {},
	"unknown":                {},
}

func cleanString(value string) string {
	value = strings.Trim(value, "\x00 \t\r\n")
	if value == "" {
		return ""
	}
	normalized := strings.ToLower(strings.Join(strings.Fields(value), " "))
	if _, placeholder := firmwarePlaceholders[normalized]; placeholder {
		return ""
	}
	if strings.Contains(normalized, "to be filled by o.e.m") || strings.Contains(normalized, "to be filled by oem") {
		return ""
	}
	return value
}

func cleanStringPtr(value *string) string {
	if value == nil {
		return ""
	}
	return cleanString(*value)
}

func firstString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func normalizeUUID(value string) string {
	value = strings.ToLower(strings.Trim(cleanString(value), "{}"))
	if len(value) == 32 {
		value = value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:]
	}
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return ""
	}

	allZero, allF := true, true
	for i, character := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return ""
		}
		allZero = allZero && character == '0'
		allF = allF && character == 'f'
	}
	if allZero || allF {
		return ""
	}
	return value
}

func chassisType(value uint16) string {
	types := map[uint16]string{
		3: "desktop", 4: "low_profile_desktop", 5: "pizza_box", 6: "mini_tower",
		7: "tower", 8: "portable", 9: "laptop", 10: "notebook", 11: "handheld",
		12: "docking_station", 13: "all_in_one", 14: "sub_notebook", 15: "space_saving",
		16: "lunch_box", 17: "main_system_chassis", 18: "expansion_chassis",
		19: "sub_chassis", 20: "bus_expansion_chassis", 21: "peripheral_chassis",
		22: "storage_chassis", 23: "rack_mount_chassis", 24: "sealed_case_pc",
		30: "tablet", 31: "convertible", 32: "detachable", 33: "iot_gateway",
		34: "embedded_pc", 35: "mini_pc", 36: "stick_pc",
	}
	return types[value]
}

func smbiosMemoryType(value uint32) string {
	types := map[uint32]string{
		1: "other", 3: "dram", 4: "edram", 5: "vram", 6: "sram", 7: "ram",
		8: "rom", 9: "flash", 10: "eeprom", 11: "feprom", 12: "eprom",
		13: "cdram", 14: "3dram", 15: "sdram", 16: "sgram", 17: "rdram",
		18: "ddr", 19: "ddr2", 20: "ddr2_fb_dimm", 24: "ddr3", 25: "fbd2",
		26: "ddr4", 27: "lpddr", 28: "lpddr2", 29: "lpddr3", 30: "lpddr4",
		31: "logical_non_volatile", 32: "hbm", 33: "hbm2", 34: "ddr5",
		35: "lpddr5", 36: "hbm3",
	}
	return types[value]
}

func memoryFormFactor(value uint16) string {
	forms := map[uint16]string{
		2: "sip", 3: "dip", 4: "zip", 5: "soj", 6: "proprietary", 7: "simm",
		8: "dimm", 9: "tsop", 10: "pga", 11: "rimm", 12: "sodimm", 13: "srimm",
		14: "smd", 15: "ssmp", 16: "qfp", 17: "tqfp", 18: "soic", 19: "lif",
		20: "plcc", 21: "bga", 22: "fpbga", 23: "lga", 24: "die",
	}
	return forms[value]
}

func normalizeMAC(value string) string {
	if value == "" {
		return ""
	}
	address, err := net.ParseMAC(value)
	if err != nil || len(address) != 6 {
		return ""
	}
	allZero, allF := true, true
	for _, octet := range address {
		allZero = allZero && octet == 0
		allF = allF && octet == 0xff
	}
	if allZero || allF {
		return ""
	}
	return strings.ToUpper(address.String())
}

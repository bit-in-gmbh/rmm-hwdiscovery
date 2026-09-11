//go:build windows && (amd64 || arm64)

package hwdiscovery

import "strings"

func normalizeBusType(value *uint16) string {
	if value == nil {
		return ""
	}
	types := map[uint16]string{
		1: "scsi", 2: "atapi", 3: "ata", 4: "ieee_1394", 5: "ssa",
		6: "fibre_channel", 7: "usb", 8: "raid", 9: "iscsi", 10: "sas",
		11: "sata", 12: "sd", 13: "mmc", 14: "virtual", 15: "file_backed_virtual",
		16: "storage_spaces", 17: "nvme", 18: "scm", 19: "ufs", 20: "nvme_of",
	}
	return types[*value]
}

func normalizeBusString(value string) string {
	switch strings.ToLower(cleanString(value)) {
	case "ide", "ata":
		return "ata"
	case "1394", "ieee 1394", "ieee_1394":
		return "ieee_1394"
	case "fibre channel", "fibre_channel":
		return "fibre_channel"
	case "nvme", "pci", "raid", "sas", "sata", "scsi", "sd", "usb":
		return strings.ToLower(cleanString(value))
	default:
		return ""
	}
}

func normalizeDiskMediaType(value *uint16) string {
	if value == nil {
		return ""
	}
	switch *value {
	case 3:
		return "hdd"
	case 4:
		return "ssd"
	case 5:
		return "scm"
	default:
		return ""
	}
}

func normalizeDiskMediaString(value string) string {
	value = strings.ToLower(cleanString(value))
	switch {
	case strings.Contains(value, "solid state") || value == "ssd":
		return "ssd"
	case strings.Contains(value, "hard disk") || strings.Contains(value, "fixed") || value == "hdd":
		return "hdd"
	case strings.Contains(value, "removable"):
		return "removable"
	case strings.Contains(value, "optical"):
		return "optical"
	default:
		return ""
	}
}

func normalizePartitionStyle(value *uint16) string {
	if value == nil {
		return ""
	}
	switch *value {
	case 1:
		return "mbr"
	case 2:
		return "gpt"
	default:
		return ""
	}
}

func inferPartitionStyle(value string) string {
	value = strings.ToLower(cleanString(value))
	switch {
	case strings.Contains(value, "gpt"):
		return "gpt"
	case strings.Contains(value, "mbr"):
		return "mbr"
	default:
		return ""
	}
}

func normalizeVolumeID(value string) string {
	value = cleanString(value)
	if len(value) == 2 && value[1] == ':' {
		return strings.ToUpper(value)
	}
	return value
}

func volumeMountPoint(id string) string {
	if len(id) == 2 && id[1] == ':' {
		return id + `\`
	}
	return id
}

func associationDeviceID(reference, class string) string {
	if reference == "" {
		return ""
	}
	needle := strings.ToLower(class + ".DeviceID=")
	index := strings.Index(strings.ToLower(reference), needle)
	if index < 0 {
		return ""
	}
	value := strings.TrimSpace(reference[index+len(needle):])
	if len(value) < 2 || value[0] != '"' {
		return cleanString(value)
	}
	value = value[1:]
	if end := strings.LastIndexByte(value, '"'); end >= 0 {
		value = value[:end]
	}
	value = strings.ReplaceAll(value, `\\`, `\`)
	value = strings.ReplaceAll(value, `\"`, `"`)
	return cleanString(value)
}

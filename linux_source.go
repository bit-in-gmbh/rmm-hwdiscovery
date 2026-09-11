//go:build linux && (amd64 || arm64)

package hwdiscovery

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type linuxSource struct {
	sysRoot    string
	procRoot   string
	runRoot    string
	devRoot    string
	pciIDPaths []string
}

func defaultLinuxSource() linuxSource {
	return linuxSource{
		sysRoot:  "/sys",
		procRoot: "/proc",
		runRoot:  "/run",
		devRoot:  "/dev",
		pciIDPaths: []string{
			"/usr/share/hwdata/pci.ids",
			"/usr/share/misc/pci.ids",
			"/usr/share/pci.ids",
		},
	}
}

func (s linuxSource) sys(parts ...string) string {
	return filepath.Join(append([]string{s.sysRoot}, parts...)...)
}

func (s linuxSource) proc(parts ...string) string {
	return filepath.Join(append([]string{s.procRoot}, parts...)...)
}

func (s linuxSource) run(parts ...string) string {
	return filepath.Join(append([]string{s.runRoot}, parts...)...)
}

func readClean(path string) string {
	value, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return cleanLinuxString(string(value))
}

func cleanLinuxString(value string) string {
	value = cleanString(value)
	switch strings.ToLower(strings.Join(strings.Fields(value), " ")) {
	case "not defined", "no asset tag":
		return ""
	default:
		return value
	}
}

func readUint(path string, bitSize int) (uint64, bool) {
	value := readClean(path)
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 0, bitSize)
	return parsed, err == nil
}

func readProperties(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	properties := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "E:") {
			line = line[2:]
		}
		key, value, found := strings.Cut(line, "=")
		if found && key != "" {
			properties[key] = cleanLinuxString(value)
		}
	}
	return properties
}

func deviceProperties(start, stop string) map[string]string {
	start, err := filepath.EvalSymlinks(start)
	if err != nil {
		return nil
	}
	stop, _ = filepath.Abs(stop)
	for path := start; path != "." && path != string(filepath.Separator); path = filepath.Dir(path) {
		if properties := readProperties(filepath.Join(path, "uevent")); len(properties) > 0 {
			if properties["MODALIAS"] != "" || properties["PCI_SLOT_NAME"] != "" {
				return properties
			}
		}
		if path == stop || !pathWithin(path, stop) {
			break
		}
	}
	return nil
}

func pathWithin(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func naturalLess(left, right string) bool {
	for len(left) > 0 && len(right) > 0 {
		leftDigit := left[0] >= '0' && left[0] <= '9'
		rightDigit := right[0] >= '0' && right[0] <= '9'
		if leftDigit && rightDigit {
			leftEnd, rightEnd := 0, 0
			for leftEnd < len(left) && left[leftEnd] >= '0' && left[leftEnd] <= '9' {
				leftEnd++
			}
			for rightEnd < len(right) && right[rightEnd] >= '0' && right[rightEnd] <= '9' {
				rightEnd++
			}
			leftNumber, _ := strconv.ParseUint(left[:leftEnd], 10, 64)
			rightNumber, _ := strconv.ParseUint(right[:rightEnd], 10, 64)
			if leftNumber != rightNumber {
				return leftNumber < rightNumber
			}
			left, right = left[leftEnd:], right[rightEnd:]
			continue
		}
		if left[0] != right[0] {
			return left[0] < right[0]
		}
		left, right = left[1:], right[1:]
	}
	return len(left) < len(right)
}

func sortedDirNames(path string) []string {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Slice(names, func(i, j int) bool { return naturalLess(names[i], names[j]) })
	return names
}

func firstNULString(value []byte) string {
	if index := strings.IndexByte(string(value), 0); index >= 0 {
		value = value[:index]
	}
	return cleanLinuxString(string(value))
}

type pciDatabase struct {
	vendors map[string]string
	devices map[string]map[string]string
}

func loadPCIDatabase(paths []string) pciDatabase {
	database := pciDatabase{vendors: make(map[string]string), devices: make(map[string]map[string]string)}
	var data []byte
	for _, path := range paths {
		var err error
		data, err = os.ReadFile(path)
		if err == nil {
			break
		}
	}
	if len(data) == 0 {
		return database
	}
	currentVendor := ""
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] != '\t' {
			fields := strings.Fields(line)
			if len(fields) < 2 || len(fields[0]) != 4 {
				currentVendor = ""
				continue
			}
			currentVendor = strings.ToLower(fields[0])
			database.vendors[currentVendor] = cleanLinuxString(strings.TrimSpace(line[len(fields[0]):]))
			continue
		}
		if strings.HasPrefix(line, "\t\t") || currentVendor == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || len(fields[0]) != 4 {
			continue
		}
		if database.devices[currentVendor] == nil {
			database.devices[currentVendor] = make(map[string]string)
		}
		database.devices[currentVendor][strings.ToLower(fields[0])] = cleanLinuxString(strings.TrimSpace(trimmed[len(fields[0]):]))
	}
	return database
}

func (d pciDatabase) lookup(vendor, device string) (string, string) {
	vendor = strings.TrimPrefix(strings.ToLower(vendor), "0x")
	device = strings.TrimPrefix(strings.ToLower(device), "0x")
	return d.vendors[vendor], d.devices[vendor][device]
}

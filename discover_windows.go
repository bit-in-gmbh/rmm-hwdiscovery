//go:build windows && (amd64 || arm64)

package hwdiscovery

import (
	"errors"

	"github.com/yusufpapurcu/wmi"
)

const cimv2Namespace = `root\cimv2`

type queryer interface {
	Query(namespace, query string, dst any) error
}

type localWMIQueryer struct {
	client *wmi.Client
}

func (q *localWMIQueryer) Query(namespace, query string, dst any) error {
	if namespace == "" || namespace == cimv2Namespace {
		return q.client.Query(query, dst)
	}
	return q.client.Query(query, dst, nil, namespace)
}

// Discover returns a best-effort inventory of static hardware identity and
// configuration available through local WMI. Failed or inaccessible queries
// omit only their unavailable data.
func Discover() Inventory {
	return discover(&localWMIQueryer{client: &wmi.Client{
		NonePtrZero:        true,
		PtrNil:             true,
		AllowMissingFields: true,
	}})
}

func discover(q queryer) Inventory {
	system, installedPhysicalBytes := collectSystem(q)
	return Inventory{
		System:          system,
		Memory:          collectMemory(q, installedPhysicalBytes),
		Processors:      collectProcessors(q),
		Disks:           collectDisks(q),
		NetworkAdapters: collectNetworkAdapters(q),
		GPUs:            collectGPUs(q),
	}
}

func queryClass(q queryer, namespace, class string, dst any) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("WMI query panicked")
		}
	}()
	return q.Query(namespace, wmi.CreateQuery(dst, "", class), dst)
}

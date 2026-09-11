# Windows Hardware Discovery Module v1.0.0

## Summary

Build `github.com/bit-in-gmbh/bigrmm-hwdiscovery` as package `hwdiscovery`: a dependency-light, best-effort hardware inventory library with a platform-neutral API and stable JSON representation.

Windows 10/11 and Windows Server 2016+ on amd64/arm64 are supported initially. Linux and macOS compile successfully but return an empty inventory until later collectors are implemented. The module never starts external processes and collects no monitoring metrics.

Implementation will use local WMI-over-COM through the MIT-licensed [`yusufpapurcu/wmi`](https://pkg.go.dev/github.com/yusufpapurcu/wmi) library. It will independently implement the relevant concepts from [`ghw`](https://github.com/jaypipes/ghw), following its hardware-inspection rather than monitoring boundary.

## Public API and Data Model

- Expose only `func Discover() Inventory`; no constructors, options, loggers, callbacks, or public errors.
- Use exported Go structs with snake-case JSON tags and `omitempty`. Missing classes, properties, or failed queries are silently absent.
- Define:
  - `Inventory`: optional `System`, `Memory`; slices of `Processor`, `Disk`, `NetworkAdapter`, and `GPU`.
  - `System`: manufacturer, model, family, version, serial number, UUID, SKU, normalized system type, and optional `Chassis`, `Baseboard`, and `Firmware`.
  - `Processor`: ID, manufacturer, model, architecture, socket, physical-core count, logical-processor count, and maximum clock MHz.
  - `Memory`: installed physical bytes and `MemoryModule` entries containing bank/location, vendor, part/serial numbers, capacity, configured/rated MT/s, memory type, and form factor.
  - `Disk`: ID/index, PnP ID, vendor/model/serial, capacity, logical/physical sector sizes, normalized media/bus/partition-table types, and nested partitions.
  - `Partition`: ID/index, byte size, starting byte offset, and nested volumes.
  - `Volume`: volume ID, label, filesystem, byte capacity, and mount points; never free or used capacity.
  - `NetworkAdapter`: stable ID, name/model/vendor, normalized physical medium, MAC address, and PnP ID; include only adapters positively identified as physical.
  - `GPU`: stable/PnP ID, name, manufacturer, and video processor.
- Normalize units in field names, enum strings to lowercase stable values, MAC addresses to canonical form, BIOS dates to `YYYY-MM-DD`, and UUIDs to lowercase canonical form.
- Trim NULs/whitespace and omit known firmware placeholders such as `Unknown`, `None`, `Default string`, OEM filler text, and all-zero/all-`F` UUIDs.
- Sort all component slices by stable ID or hardware index for deterministic JSON. Module SemVer governs both the exported Go API and JSON field contract; no runtime version constant is added.

## Implementation

- Keep platform-neutral types in the root package, with build-tagged discovery implementations. Unsupported platforms and unsupported Windows architectures return `Inventory{}`.
- Add an unexported WMI query interface and `discover(queryer)` path so collectors can be fixture-tested without exposing configuration publicly.
- Query local WMI sequentially and independently:
  - System: `Win32_ComputerSystem`, `Win32_ComputerSystemProduct`, `Win32_SystemEnclosure`, `Win32_BaseBoard`, and `Win32_BIOS`.
  - CPU and memory: `Win32_Processor` and `Win32_PhysicalMemory`.
  - Storage: `Win32_DiskDrive`, `Win32_DiskPartition`, `Win32_LogicalDiskToPartition`, and `Win32_LogicalDisk`, with optional `MSFT_Disk`/`MSFT_PhysicalDisk` enrichment from the Storage namespace. Never request `FreeSpace`, health, power-on hours, or operational state.
  - Network and graphics: `Win32_NetworkAdapter` and `Win32_VideoController`.
- Preserve base entities if optional enrichment or association queries fail. Skip an entity only when its minimum identity/correlation data is unavailable.
- Do not query CPU load/current clock, available RAM, disk usage/SMART health, network addresses/link state/current speed, GPU load/temperature, or other transient values.
- Forbid `os/exec`, shell invocation, PowerShell, `wmic`, `system_profiler`, `dmidecode`, `ethtool`, and equivalent process creation. WMI is accessed directly through Windows COM, whose architecture is documented by [Microsoft](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-architecture).

## Licensing, Documentation, and Versioning

- License the project under Apache-2.0.
- Add `ACKNOWLEDGMENTS.md` containing:
  - `ghw`, Apache-2.0, Jay Pipes and contributors, the reviewed commit `72554a2b7284f5e5d9ab15305a4a710d79dd2299`, and its role as a functional/design reference.
  - `github.com/yusufpapurcu/wmi v1.2.4`, MIT, Copyright 2013 Stack Exchange, including its required notice.
  - `github.com/go-ole/go-ole v1.2.6`, MIT, Copyright 2013–2017 Yasuhiro Matsumoto, including its required notice.
- Do not add `ghw` as a dependency or copy it wholesale. Any later code adaptation must retain attribution, identify the source commit/file, and carry a modification notice.
- Add:
  - `README.md` with usage, JSON example, support matrix, omission behavior, security/privacy implications of hardware identifiers, and discovery-versus-monitoring boundaries.
  - `CHANGELOG.md` declaring the initial `1.0.0` release.
  - Package documentation for exported types and omission/unit semantics.
  - Root `AGENTS.md` enforcing KISS/YAGNI, platform build tags, no subprocesses, no dynamic metrics, stable JSON/API rules, license review, acknowledgment updates, and required validation.
- Leave the repository release-ready but do not create or publish a `v1.0.0` tag.

## Tests and Delivery

- Add fixture-driven tests for complete inventory mapping, deterministic JSON, enum/unit normalization, storage associations, physical-NIC filtering, and placeholder removal.
- Verify nil WMI properties never panic and individual query failures silently omit only the affected data.
- Add a source-policy test rejecting production imports of `os/exec` and equivalent explicit process-launch APIs.
- Test non-Windows builds return an empty inventory.
- Run Windows amd64 unit and live WMI smoke tests; cross-build Windows arm64; build/test Linux and macOS stubs; run `gofmt`, `go vet`, and `go test ./...`.
- Deliver in incremental commits:
  1. Project policy, Apache license, acknowledgments, and module dependencies.
  2. Portable inventory types, JSON contract, and unsupported-platform implementation.
  3. Windows system, firmware, CPU, and memory collectors.
  4. Windows storage, network, and GPU collectors.
  5. Tests, CI, README, package documentation, and `1.0.0` changelog.

## Assumptions

- Discovery targets only the local machine and does not use remote WMI.
- No administrator elevation is attempted; inaccessible information is omitted.
- Normal development commands such as `go test` are allowed—the no-external-tool rule applies to runtime module behavior.
- Windows 386 and pre-Windows-10/pre-Server-2016 systems are unsupported.
- The existing Go 1.27 module directive and module path remain unchanged.

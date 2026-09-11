# Repository Guidance

Keep this package small, dependency-light, and best-effort. Apply KISS and YAGNI: add only hardware inventory needed by the public contract.

- Keep exported types and `Discover()` platform-neutral. Put platform code behind precise build tags; unsupported platforms and Windows architectures must compile and return `Inventory{}`.
- Never start subprocesses from production code. Do not import `os/exec`, invoke shells, PowerShell, `wmic`, or other external discovery utilities.
- Collect static hardware identity and configuration only. Do not add load, utilization, free/used capacity, health, temperature, link state, current speed, power-on time, or other monitoring metrics.
- Treat the exported Go API and snake-case JSON names as a stable SemVer contract. New optional data must use `omitempty`; normalize units in field names and sort slices deterministically.
- Discovery is local, sequential, independent, and best-effort. A failed read/query or missing kernel/WMI property must not panic or discard otherwise usable entities.
- Review licenses before adding or adapting code or dependencies. Update `ACKNOWLEDGMENTS.md` with source, version/commit, license, copyright, role, and modification notice where applicable.
- Before delivery run `gofmt`, `go vet ./...`, and `go test ./...`; cross-build supported Windows targets and compile/test unsupported-platform stubs when feasible.

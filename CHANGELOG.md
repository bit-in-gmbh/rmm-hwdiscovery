# Changelog

All notable changes to this project are documented in this file.

## Unreleased

- Added complete best-effort macOS hardware discovery on amd64 and arm64 through Darwin sysctls and the in-process CoreFoundation, IOKit, Disk Arbitration, and System Configuration frameworks, with a sysctl-only fallback for cgo-disabled builds.
- Added macOS system, processor, installed-memory and optional SMBIOS module, physical-storage, partition and volume, physical-network-adapter, and GPU fixture coverage.
- Added complete best-effort Linux hardware discovery on amd64 and arm64 using procfs, sysfs, DMI/SMBIOS, device-tree, mount information, and optional read-only udev/PCI metadata.
- Added Linux system, processor, memory-module, physical-storage, layered-volume, physical-network-adapter, and GPU fixture coverage.
- Added best-effort processor serial-number discovery on supported Windows systems and expanded serial-number contract coverage for memory modules and physical disks.

## 1.0.0 - 2026-09-11

- Added the stable, platform-neutral hardware inventory API and JSON contract.
- Added best-effort local WMI discovery for Windows 10/11 and Windows Server 2016+ on amd64 and arm64.
- Added system, chassis, baseboard, firmware, processor, memory, storage, physical network adapter, and GPU inventory.
- Added deterministic normalization and ordering, fixture coverage, live-WMI smoke coverage, unsupported-platform stubs, and source-policy validation.

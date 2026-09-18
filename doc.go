// Package hwdiscovery provides a best-effort inventory of static hardware
// identity and configuration.
//
// Call [Discover] to inspect the local system. Discovery is sequential, starts
// no external programs, and reports failures by omitting only the unavailable
// data. On unsupported platforms it returns an empty [Inventory].
//
// Byte counts are exact bytes, clock rates are MHz, and memory transfer rates
// are MT/s. Dates use YYYY-MM-DD. Collections are sorted deterministically.
// Zero-valued and unavailable fields are omitted when an inventory is encoded
// as JSON.
package hwdiscovery

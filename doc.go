// Package hwdiscovery provides a best-effort inventory of static hardware
// identity and configuration.
//
// Discover never starts external programs and never returns an error. Data that
// is unavailable, unsupported, or inaccessible is omitted. Byte counts are
// exact bytes, clock rates are MHz, and memory transfer rates are MT/s.
package hwdiscovery

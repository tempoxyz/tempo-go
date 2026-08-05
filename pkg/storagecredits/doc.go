// Package storagecredits provides helpers for the T7 storage credits feature.
//
// Storage credits (TIP-1060) lower storage gas costs when an account reuses
// storage it previously freed. Deleting a storage slot mints one credit for the
// owning account; creating a slot later can consume a credit to offset the
// storage creation cost. Credits are per-account, non-transferable, and
// non-expiring.
//
// # Storage Credits precompile (TIP-1060)
//
// The precompile lives at 0x1060000000000000000000000000000000000000 and lets
// each account read its credit state and choose how credits apply to its own
// storage creations:
//   - balanceOf: read an account's credit balance
//   - modeOf: read an account's current storage creation mode
//   - budgetOf: read an account's remaining Direct-spend budget
//   - setMode: choose Refund (default), Preserve, or Direct mode
//   - setBudget: switch to Direct mode with a bounded credit budget
//
// Mode and budget are transaction-local: they reset every transaction, so a
// contract wanting non-default behavior must call setMode or setBudget in each
// transaction.
//
// # StablecoinDEX order storage credits (TIP-1064)
//
// The StablecoinDEX tracks per-user order storage credits and exposes them via
// the storageCredits(address) view. See DEXStorageCredits.
package storagecredits

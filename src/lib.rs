// ── CipherAI Library Crate Root ────────────────────────────────────
//
// This file enables integration tests (in tests/) to access all
// public modules and functions in the crate.

pub mod attack;
pub mod ci;
pub mod config;
pub mod deps;
pub mod finding;
pub mod fix;
pub mod groq;
pub mod indexer;
pub mod llm;
pub mod output;
pub mod pentest;
pub mod pr;
pub mod rag;
pub mod report;
pub mod review;
pub mod scan;
pub mod sbom;
pub mod secrets;
pub mod trace;
pub mod verify;
pub mod watch;
pub mod zeroday;

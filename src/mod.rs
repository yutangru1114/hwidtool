// mod.rs - Module Exports
// This file exposes all 15 spoofing modules

// Core spoofing modules
pub mod disk_serial;
pub mod mac_address;
pub mod motherboard;
pub mod system_uuid;
pub mod cpu_id;
pub mod gpu_id;
pub mod pci_devices;
pub mod registry_clean;
pub mod wmi_spoof;
pub mod volume_serial;
pub mod network_stack;
pub mod bios_info;
pub mod acpi_tables;
pub mod driver_hooks;
pub mod evasion;

// Re-export commonly used functions for convenience
pub use disk_serial::{spoof_disk_serial, generate_disk_serial, verify_disk_spoof};
pub use mac_address::{spoof_mac_address, generate_mac_address, list_network_adapters};
pub use motherboard::{spoof_motherboard, generate_motherboard_serial, generate_system_uuid};
pub use system_uuid::spoof_system_uuid;
pub use cpu_id::spoof_cpu_id;
pub use gpu_id::spoof_gpu_id;
pub use pci_devices::hide_pci_devices;
pub use registry_clean::clean_registry_artifacts;
pub use wmi_spoof::hook_wmi_queries;
pub use volume_serial::spoof_volume_serial;
pub use network_stack::spoof_network_stack;
pub use bios_info::spoof_bios_info;
pub use acpi_tables::inject_acpi_override;
pub use driver_hooks::install_driver_hooks;
pub use evasion::{check_debugger, check_vm, check_sandbox, enable_anti_analysis};

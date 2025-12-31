use std::path::Path;
use std::fs;
use std::env;
use sha2::{Sha256, Digest};

fn main() {
    // Embed and encrypt extra.exe (SIMPLY OUR PRIVATE MODULE)
    // We do not give source of our private modules but here is how they are implemented:
    // We simply do not give out source of private kernal functions because they are dangerous.
    // and will get patched very fast, its an cat and mouse game
    let out_dir = env::var("OUT_DIR").unwrap();
    let exe_path = Path::new("assets/extra.exe");
    
    if exe_path.exists() {
        println!("cargo:rerun-if-changed=assets/extra.exe");
        
        // Read the exe
        let exe_data = fs::read(exe_path).expect("Failed to read assets/extra.exe");
        println!("cargo:warning=Embedding extra.exe ({} bytes)", exe_data.len());
        
        // Encrypt with SHA256 key (same as decryption in main.rs)
        let key_source = b"hwidspoof.net_2025_encryption_key_v1.4.2";
        let mut hasher = Sha256::new();
        hasher.update(key_source);
        let key = hasher.finalize();
        
        let encrypted: Vec<u8> = exe_data
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key[i % key.len()])
            .collect();
        
        // Write encrypted binary
        let dest_path = Path::new(&out_dir).join("embedded_exe.bin");
        fs::write(&dest_path, encrypted).expect("Failed to write embedded_exe.bin");
        
        println!("cargo:warning=✓ extra.exe encrypted and embedded");
    } else {
        println!("cargo:warning=⚠ assets/extra.exe not found - creating empty placeholder");
        
        // Create empty file so compilation doesn't fail
        let dest_path = Path::new(&out_dir).join("embedded_exe.bin");
        fs::write(&dest_path, &[]).expect("Failed to write empty embedded_exe.bin");
    }
    
    // Only run Windows resource compilation on Windows
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();

        // Optional icon
        if Path::new("assets/icon.ico").exists() {
            res.set_icon("assets/icon.ico");
            println!("cargo:rerun-if-changed=assets/icon.ico");
        }

        // Standard metadata
        res.set_language(0x0409) // en-US
            .set("ProductName", "HWID Spoofer")
            .set("FileDescription", "Hardware ID Modification Tool")
            .set("LegalCopyright", "Copyright (c) 2025 hwidspoof.net")
            .set("CompanyName", "hwidspoof.net")
            .set("ProductVersion", "1.4.2.0")
            .set("FileVersion", "1.4.2.0")
            .set_manifest(r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    version="1.0.0.0"
    processorArchitecture="amd64"
    name="HWID Spoofer"
    type="win32"
  />
  <description>Hardware ID Modification Tool</description>

  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>

  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/> <!-- Windows 10 -->
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/> <!-- Windows 11 -->
    </application>
  </compatibility>

  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">
        PerMonitorV2
      </dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"#);

        if let Err(e) = res.compile() {
            eprintln!("Warning: failed to compile Windows resources: {}", e);
        }
    }
}
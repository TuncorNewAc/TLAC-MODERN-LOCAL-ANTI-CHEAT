use anti_cheat::messages::AntiCheatMessage;
use anti_cheat::sync_client::SyncClient;
use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rusqlite::{Connection, Error as SqliteError};
use sha2::{Sha256, Digest};
use serde::Deserialize;
use nix::sys::ptrace;
use nix::unistd::Pid;
use procfs::process::Process;
use std::env;
use std::fs;
use std::path::Path;

mod messages;
// mod server;
mod sync_client;

#[derive(Deserialize, Debug)]
struct AntiCheatConfig 
{
    expected_binary_hash: String,
    version: String,
    #[serde(default = "default_interval")]
    scan_interval_ms: u64,
    log_path: String,
}

fn default_interval() -> u64 { 5000 }

fn load_config(path: &str) -> Result<AntiCheatConfig, Box<dyn std::error::Error>>
{
    if !Path::new(path).exists()
    {
        return Err(format!("❌ Config dosyası bulunamadı: {}", path).into());
    }
    let content = fs::read_to_string(path)?;
    let config: AntiCheatConfig = serde_json::from_str(&content)?;
    Ok(config)
}

fn attach_to_process(pid: u32) -> nix::Result<()>
{
    let pid = Pid::from_raw(pid as i32);
    ptrace::attach(pid)?;
    println!("Process {} attached!", pid);
    Ok(())
}

fn detach_from_process(pid: u32) -> nix::Result<()>
{
    let pid = Pid::from_raw(pid as i32);
    ptrace::detach(pid, None)?;
    println!("Process {} detached.", pid);
    Ok(())
}

fn read_process_maps(pid: u32) -> procfs::ProcResult<()>
{
    let proc = Process::new(pid as i32)?;
    for map in proc.maps()?
    {
        let pathname_str = match &map.pathname
        {
            procfs::process::MMapPath::Path(path) => path.display().to_string(),
            procfs::process::MMapPath::Heap => "[heap]".to_string(),
            procfs::process::MMapPath::Stack => "[stack]".to_string(),
            procfs::process::MMapPath::Vvar => "[vvar]".to_string(),
            procfs::process::MMapPath::Vdso => "[vdso]".to_string(),
            procfs::process::MMapPath::Vsyscall => "[vsyscall]".to_string(),
            procfs::process::MMapPath::Other(s) => format!("[{}]", s),
            _ => "[unknown]".to_string(),
        };
        println!("{:x}-{:x} {:?} {:x} {:?} {}", map.address.0, map.address.1, map.perms, map.offset, map.dev, pathname_str);
    }
    Ok(())
}

fn read_memory_at_address(pid: u32, address: usize) -> nix::Result<i32>
{
    let pid = Pid::from_raw(pid as i32);
    let data = ptrace::read(pid, address as *mut std::ffi::c_void)?;
    Ok(data as i32)
}

fn read_memory_range(pid: u32, start: usize, len: usize) -> nix::Result<Vec<u8>>
{
    let mut data = Vec::with_capacity(len);
    let pid = Pid::from_raw(pid as i32);
    for offset in (0..len).step_by(4)
    {
        let addr = (start + offset) as *mut std::ffi::c_void;
        let word = ptrace::read(pid, addr)? as u32;
        data.extend_from_slice(&word.to_ne_bytes());
    }
    Ok(data)
}

fn search_pattern_in_memory(pid: u32, start: usize, len: usize, pattern: &[u8]) -> Option<usize>
{
    if let Ok(memory) = read_memory_range(pid, start, len)
    {
        if let Some(pos) = search_pattern_in_bytes(&memory, pattern)
        {
            return Some(start + pos);
        }
    }
    None
}

fn search_pattern_in_bytes(bytes: &[u8], pattern: &[u8]) -> Option<usize>
{
    bytes.windows(pattern.len()).position(|window| window == pattern)
}

fn search_wildcard_pattern_in_bytes(bytes: &[u8], pattern: &[Option<u8>]) -> Option<usize>
{
    let pat_len = pattern.len();
    for i in 0..=(bytes.len() - pat_len)
    {
        let mut matched = true;
        for j in 0..pat_len
        {
            if let Some(expected_byte) = pattern[j]
            {
                if bytes[i + j] != expected_byte
                {
                    matched = false;
                    break;
                }
            }
        }
        if matched
        {
            return Some(i);
        }
    }
    None   
}

fn search_wildcard_pattern_in_memory(pid: u32, start: usize, len: usize, pattern: &[Option<u8>]) -> Option<usize> {
    if let Ok(memory) = read_memory_range(pid, start, len) 
    {
        if let Some(pos) = search_wildcard_pattern_in_bytes(&memory, pattern)
        {
            return Some(start + pos);
        }
    }
    None
}

fn scan_process_for_cheat_signatures(pid: u32, signatures: &[Vec<Option<u8>>]) -> procfs::ProcResult<()>
{
    let proc = Process::new(pid as i32)?;
    let pid_struct = Pid::from_raw(pid as i32);
    match ptrace::attach(pid_struct)
    {
        Ok(_) => {},
        Err(e) => return Err(procfs::ProcError::Other(e.to_string())),
    }
    println!("Attached to process {}", pid);
    for map in proc.maps()?
    {
        if map.perms.contains(procfs::process::MMPermissions::READ) && map.perms.contains(procfs::process::MMPermissions::PRIVATE)
        {
            if let procfs::process::MMapPath::Path(_) = &map.pathname
            {
                let start = map.address.0 as usize;
                let len = (map.address.1 - map.address.0) as usize;
                for sig in signatures
                {
                    if let Some(found_at) = search_wildcard_pattern_in_memory(pid, start, len, sig)
                    {
                        println!("!!! CHEAT SIGNATURE FOUND at {:#x} in range {:#x}-{:#x}", found_at, start, map.address.1);
                    }
                }
            }
        }
    }
    match ptrace::detach(pid_struct, None)
    {
        Ok(_) => {},
        Err(e) => return Err(procfs::ProcError::Other(e.to_string())),
    }
    println!("Detached from process {}", pid);
    Ok(())
}

fn calculate_binary_hash() -> Result<String, Box<dyn std::error::Error>> 
{
    let exe_path = env::current_exe()?;
    let content = fs::read(exe_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

fn verify_binary_integrity(expected_hash: &str) -> Result<(), Box<dyn std::error::Error>>
{
    let current_hash = calculate_binary_hash()?;
    if current_hash != expected_hash
    {
        return Err(format!("!!! BINARY TAMPERING DETECTED!\nExpected: {}\nGot: {}", expected_hash, current_hash).into());
    }
    println!("✅ Binary integrity verified.");
    Ok(())
}

async fn send_to_server(socket_path: &str, msg: &AntiCheatMessage) -> Result<(), Box<dyn std::error::Error>>
{
    let mut stream = UnixStream::connect(socket_path).await?;
    
    let data = serde_json::to_vec(msg)?;
    stream.write_all(&data).await?;
    
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf).await;
    
    Ok(())
}

async fn report_suspicious_activity(pid: u32, reason: String, socket_path: &str)
{
    let msg = AntiCheatMessage::SuspiciousActivity
    {
        pid,
        reason,
        memory_address: None,
        signature_found: None,
    };
    if let Err(e) = send_to_server(socket_path, &msg).await
    {
        eprintln!("❌ Failed to report to server: {}", e);
    }
}

fn init_db() -> Result<Connection, Box<dyn std::error::Error>> 
{
    let conn = Connection::open("anti_cheat.db")?;
    conn.execute("CREATE TABLE IF NOT EXISTS hwid_bans (...)", [],)?;
    Ok(conn)
}

fn generate_hwid() -> String
{
    let mut hasher = Sha256::new();
    
    if let Ok(uuid) = fs::read_to_string("/sys/class/dmi/id/product_uuid") 
    {
        hasher.update(uuid.trim());
    }
    
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") 
    {
        if let Some(serial) = cpuinfo.lines().find(|l| l.starts_with("serial")) 
        {
            hasher.update(serial);
        }
    }
    
    if let Ok(mac) = fs::read_to_string("/sys/class/net/eth0/address") 
    {
        hasher.update(mac.trim());
    } 
    else if let Ok(mac) = fs::read_to_string("/sys/class/net/wlan0/address")
    {
        hasher.update(mac.trim());
    }

    if let Ok(serial) = fs::read_to_string("/sys/block/sda/device/serial")
    {
        hasher.update(serial.trim());
    }

    format!("{:x}", hasher.finalize())
}

fn is_hwid_banned(conn: &Connection, hwid: &str) -> std::result::Result<bool, Box<dyn std::error::Error>>
{
    let count: u32 = conn.query_row
    (
        "SELECT COUNT(*) FROM hwid_bans WHERE hwid = ?1",
        [hwid],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn ban_hwid(conn: &Connection, hwid: &str, reason: &str) -> Result<(), SqliteError>
{
    conn.execute(
        "INSERT OR IGNORE INTO hwid_bans (hwid, reason) VALUES (?1, ?2)",
        [hwid, reason],
    )?;
    Ok(())
}

#[tokio::main]
async fn main()
{
    let hwid = generate_hwid();
    let conn = init_db().expect("Veritabanı açılamadı");
    let local_count: u32 = conn.query_row
    (
        "SELECT COUNT(*) FROM hwid_bans", [], |row| row.get(0)
    ).unwrap_or(0);
    let sync_client = SyncClient::new("http://127.0.0.1:5000");
    match sync_client.sync_bans(&hwid, local_count).await 
    {
        Ok(sync_data) => {
            println!("📥 Sunucudan {} ban alındı.", sync_data.bans.len());
            for ban in &sync_data.bans 
            {
                conn.execute(
                    "INSERT OR IGNORE INTO hwid_bans (hwid, reason, banned_at) VALUES (?1, ?2, ?3)",
                    [&ban.hwid, &ban.reason, &ban.banned_at],
                ).ok(); // Hata olsa bile devam et
            }
        }
        Err(e) => 
        {
            eprintln!("⚠️ Sync başarısız, yerel veritabanı kullanılıyor: {}", e);
        }
    }

    let is_banned: bool = conn.query_row
    (
        "SELECT COUNT(*) > 0 FROM hwid_bans WHERE hwid = ?1", [&hwid], |row| row.get(0)
    ).unwrap_or(false);

    if is_banned 
    {
        eprintln!("🚫 HWID banlı! Sistem başlatılamıyor.");
        std::process::exit(1);
    }

    match is_hwid_banned(&conn, &hwid)
    {
        Ok(true) =>
        {
            eprintln!("🚫 DONANIM BANLI! Sistem başlatılamıyor.");
            std::process::exit(1);
        }
        Ok(false) => println!("✅ HWID temiz: {}", hwid),
        Err(e) => eprintln!("⚠️ Ban kontrolü hatası: {}", e),
    }
    let config_path = "config.json";
    let config = match load_config(config_path)
    {
        Ok(c) => c,
        Err(e) =>
        {
            eprintln!("⛔ Config yükleme hatası: {}", e);
            std::process::exit(1);
        }
    };

    println!("🔧 Anti-Cheat v{} başlatılıyor...", config.version);

    if let Err(e) = verify_binary_integrity(&config.expected_binary_hash)
    {
        eprintln!("🚨 KRİTİK: Binary değiştirilmiş! Sistem kapatılıyor. ({})", e);
        std::process::exit(1);
    }

    println!("✅ Binary bütünlüğü doğrulandı.");

    let pid: u32 = std::env::args().nth(1).expect("Usage: <pid>").parse().expect("PID must be a number");
    let cheat_signatures = vec!
    [
        vec![Some(0x48), Some(0x89), None, Some(0xE5)],
        vec![Some(0x48), Some(0x8B), None, Some(0x05)],
    ];
    if let Err(e) = scan_process_for_cheat_signatures(pid, &cheat_signatures)
    {
        eprintln!("Scan failed: {:?}", e);
        return;
    }
    let socket_path = "/tmp/anti-cheat.sock";
    let heartbeat_msg = AntiCheatMessage::Heartbeat 
    {
        pid,
        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
    };
    let _ = send_to_server(socket_path, &heartbeat_msg).await;
}

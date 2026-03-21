//! Minimal test binary to verify eBPF programs load and attach.
//! Run: sudo ./target/release/test-ebpf
//!
//! This embeds the compiled eBPF bytecode and tests:
//! 1. Loading into kernel
//! 2. Attaching to tracepoints
//! 3. Reading events from ring buffer

#[cfg(feature = "ebpf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use aya::maps::RingBuf;
    use aya::programs::TracePoint;
    use aya::Ebpf;

    println!("Inner Warden eBPF test loader\n");

    // Load eBPF bytecode from file (in production, embedded via include_bytes!)
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        "crates/sensor-ebpf/target/bpfel-unknown-none/release/innerwarden-ebpf".to_string()
    });

    let bytes = std::fs::read(&path)?;
    println!("Loaded {} bytes from {path}", bytes.len());

    let mut bpf = Ebpf::load(&bytes)?;
    println!("eBPF object loaded into kernel ✅");

    // List available programs
    for (name, _) in bpf.programs() {
        println!("  Program: {name}");
    }
    println!();

    // Attach execve tracepoint
    let execve: &mut TracePoint = bpf.program_mut("innerwarden_execve").unwrap().try_into()?;
    execve.load()?;
    execve.attach("syscalls", "sys_enter_execve")?;
    println!("✅ innerwarden_execve → sys_enter_execve");

    // Attach connect tracepoint
    let connect: &mut TracePoint = bpf.program_mut("innerwarden_connect").unwrap().try_into()?;
    connect.load()?;
    connect.attach("syscalls", "sys_enter_connect")?;
    println!("✅ innerwarden_connect → sys_enter_connect");

    // Read ring buffer
    println!("\nListening for events (5 seconds)...\n");
    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    let start = std::time::Instant::now();
    let mut exec_count = 0u64;
    let mut connect_count = 0u64;

    while start.elapsed() < std::time::Duration::from_secs(5) {
        while let Some(item) = ring_buf.next() {
            let data = item.as_ref();
            if data.len() >= 4 {
                let kind = u32::from_ne_bytes(data[0..4].try_into().unwrap());
                match kind {
                    1 => {
                        exec_count += 1;
                        if exec_count <= 5 {
                            let pid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
                            // comm starts at offset 32 (after cgroup_id field)
                            let comm_bytes = &data[32..96];
                            let comm_end = comm_bytes.iter().position(|&b| b == 0).unwrap_or(64);
                            let comm = std::str::from_utf8(&comm_bytes[..comm_end]).unwrap_or("?");
                            println!("  EXEC  pid={pid:<6} comm={comm}");
                        }
                    }
                    2 => {
                        connect_count += 1;
                        if connect_count <= 5 {
                            let pid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
                            // comm at offset 32 (after ppid + padding + cgroup_id)
                            let comm_bytes = &data[32..96];
                            let comm_end = comm_bytes.iter().position(|&b| b == 0).unwrap_or(64);
                            let comm = std::str::from_utf8(&comm_bytes[..comm_end]).unwrap_or("?");
                            // dst_addr at offset 96, dst_port at offset 100
                            if data.len() >= 102 {
                                let addr_bytes = &data[96..100];
                                let port = u16::from_ne_bytes(data[100..102].try_into().unwrap());
                                let ip = format!(
                                    "{}.{}.{}.{}",
                                    addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]
                                );
                                println!("  CONN  pid={pid:<6} {comm} → {ip}:{port}");
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    println!("\n═══════════════════════════════════════════════");
    println!("  Execve events:  {exec_count}");
    println!("  Connect events: {connect_count}");
    println!("  Total:          {}", exec_count + connect_count);
    println!("═══════════════════════════════════════════════");
    println!("\n🎉 eBPF sensor is working!");

    Ok(())
}

#[cfg(not(feature = "ebpf"))]
fn main() {
    eprintln!("This binary requires the 'ebpf' feature. Compile with:");
    eprintln!("  cargo build --release --features ebpf -p innerwarden-sensor --bin test-ebpf");
    std::process::exit(1);
}

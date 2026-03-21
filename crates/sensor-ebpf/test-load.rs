// Quick standalone test to verify eBPF programs load and attach
// Compile: cargo build --release -p innerwarden-sensor (with aya dep)
// Run: sudo ./target/release/test-ebpf-load

use aya::programs::TracePoint;
use aya::Ebpf;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ebpf_bytes = include_bytes!("target/bpfel-unknown-none/release/innerwarden-ebpf");

    println!("Loading eBPF programs ({} bytes)...", ebpf_bytes.len());
    let mut bpf = Ebpf::load(ebpf_bytes)?;

    // Attach execve tracepoint
    let execve: &mut TracePoint = bpf.program_mut("innerwarden_execve").unwrap().try_into()?;
    execve.load()?;
    execve.attach("syscalls", "sys_enter_execve")?;
    println!("✅ innerwarden_execve attached to syscalls/sys_enter_execve");

    // Attach connect tracepoint
    let connect: &mut TracePoint = bpf.program_mut("innerwarden_connect").unwrap().try_into()?;
    connect.load()?;
    connect.attach("syscalls", "sys_enter_connect")?;
    println!("✅ innerwarden_connect attached to syscalls/sys_enter_connect");

    // Read ring buffer for 5 seconds
    println!("\nListening for 5 seconds...\n");
    let ring_buf = aya::maps::RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    let start = std::time::Instant::now();
    let mut count = 0;
    while start.elapsed() < Duration::from_secs(5) {
        while let Some(item) = ring_buf.next() {
            let data = item.as_ref();
            if data.len() >= 4 {
                let kind = u32::from_ne_bytes(data[0..4].try_into().unwrap());
                match kind {
                    1 => {
                        // ExecveEvent
                        if data.len() >= 24 {
                            let pid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
                            let uid = u32::from_ne_bytes(data[16..20].try_into().unwrap());
                            println!("EXEC pid={pid} uid={uid}");
                            count += 1;
                        }
                    }
                    2 => {
                        // ConnectEvent
                        if data.len() >= 80 {
                            let pid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
                            println!("CONNECT pid={pid}");
                            count += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    println!("\nCaptured {count} events in 5 seconds.");
    println!("eBPF sensor is working! 🎉");

    Ok(())
}

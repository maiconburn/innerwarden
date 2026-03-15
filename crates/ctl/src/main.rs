use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod capabilities;
mod capability;
mod config_editor;
mod module_manifest;
mod module_package;
mod module_validator;
mod preflight;
mod sudoers;
mod systemd;
mod upgrade;

use capability::{ActivationOptions, CapabilityRegistry};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "innerwarden",
    about = "InnerWarden control plane — manage capabilities",
    long_about = "Activate and manage InnerWarden capabilities.\n\n\
                  Run 'innerwarden list' to see available capabilities.\n\
                  Run 'innerwarden enable <id>' to activate one."
)]
struct Cli {
    /// Path to sensor config (config.toml)
    #[arg(long, default_value = "/etc/innerwarden/config.toml")]
    sensor_config: PathBuf,

    /// Path to agent config (agent.toml)
    #[arg(long, default_value = "/etc/innerwarden/agent.toml")]
    agent_config: PathBuf,

    /// Show what would happen without applying any changes
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Activate a capability
    Enable {
        /// Capability ID (run 'innerwarden list' to see options)
        capability: String,

        /// Capability-specific parameters as KEY=VALUE
        #[arg(long = "param", value_name = "KEY=VALUE", action = clap::ArgAction::Append)]
        params: Vec<String>,

        /// Skip interactive confirmation prompts (e.g. privacy gate)
        #[arg(long)]
        yes: bool,
    },

    /// Deactivate a capability
    Disable {
        /// Capability ID (run 'innerwarden list' to see options)
        capability: String,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// List all capabilities with their current status
    List,

    /// Show system status (services, capabilities, modules).
    /// Optionally narrow to a specific capability.
    Status {
        /// Capability ID to inspect (omit for global overview)
        capability: Option<String>,

        /// Directory to scan for installed modules
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,
    },

    /// Run system diagnostics and print fix hints for any issues found
    Doctor,

    /// Check for a newer release and optionally upgrade all binaries
    Upgrade {
        /// Only check if an update is available; do not install
        #[arg(long)]
        check: bool,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,

        /// Directory where binaries are installed
        #[arg(long, default_value = "/usr/local/bin")]
        install_dir: PathBuf,
    },

    /// Configure AI provider and API key
    Configure {
        #[command(subcommand)]
        command: ConfigureCommand,
    },

    /// Module management commands
    Module {
        #[command(subcommand)]
        command: ModuleCommand,
    },

    /// Local AI management
    Ai {
        #[command(subcommand)]
        command: AiCommand,
    },
}

#[derive(Subcommand)]
enum ConfigureCommand {
    /// Set AI provider: openai, anthropic, or ollama
    ///
    /// Examples:
    ///   innerwarden configure ai openai --key sk-...
    ///   innerwarden configure ai anthropic --key sk-ant-...
    ///   innerwarden configure ai ollama --model llama3.2
    Ai {
        /// Provider to use: openai, anthropic, or ollama
        provider: String,

        /// API key (required for openai and anthropic)
        #[arg(long)]
        key: Option<String>,

        /// Model to use (defaults: openai→gpt-4o-mini, anthropic→claude-haiku-4-5-20251001, ollama→llama3.2)
        #[arg(long)]
        model: Option<String>,

        /// Ollama base URL (default: http://localhost:11434)
        #[arg(long)]
        base_url: Option<String>,
    },

    /// Enable or disable the responder and control dry-run mode
    ///
    /// Examples:
    ///   innerwarden configure responder --enable
    ///   innerwarden configure responder --enable --dry-run false
    ///   innerwarden configure responder --disable
    Responder {
        /// Enable the responder (responder.enabled = true)
        #[arg(long, conflicts_with = "disable")]
        enable: bool,

        /// Disable the responder (responder.enabled = false)
        #[arg(long, conflicts_with = "enable")]
        disable: bool,

        /// Set dry-run mode: true (observe only) or false (execute for real)
        #[arg(long, value_name = "BOOL")]
        dry_run: Option<bool>,
    },
}

#[derive(Subcommand)]
enum AiCommand {
    /// Configure Ollama cloud as the AI provider (free tier, no GPU needed)
    ///
    /// Sets up InnerWarden to use the Ollama cloud API with qwen3-coder:480b —
    /// the model that scored 100% accuracy in InnerWarden's security benchmark.
    ///
    /// You need a free Ollama account and an API key:
    ///   1. Sign up at https://ollama.com
    ///   2. Go to https://ollama.com/settings/api-keys
    ///   3. Create a key and paste it when prompted (or set OLLAMA_API_KEY env var)
    ///
    /// Examples:
    ///   innerwarden ai install
    ///   innerwarden ai install --model qwen3-coder:480b
    ///   innerwarden ai install --api-key ollama_...
    Install {
        /// Model to use on Ollama cloud (default: qwen3-coder:480b — 100% benchmark accuracy)
        #[arg(long, default_value = "qwen3-coder:480b")]
        model: String,

        /// Ollama API key (skip prompt). Can also be set via OLLAMA_API_KEY env var.
        #[arg(long, value_name = "KEY")]
        api_key: Option<String>,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ModuleCommand {
    /// Validate a module package (manifest, structure, security, docs, tests)
    Validate {
        /// Path to the module directory
        path: PathBuf,

        /// Enable stricter security checks (unsafe blocks, etc.)
        #[arg(long)]
        strict: bool,
    },

    /// Enable a module (patch configs, install sudoers, restart services)
    Enable {
        /// Path to the module directory containing module.toml
        path: PathBuf,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Disable a module (revert config patches, remove sudoers, restart services)
    Disable {
        /// Path to the module directory containing module.toml
        path: PathBuf,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// List all modules found in the modules directory
    List {
        /// Directory to scan for module packages (each subdirectory with a module.toml)
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,
    },

    /// Show the status of a specific module by ID
    Status {
        /// Module ID (e.g. "search-protection")
        id: String,

        /// Directory to scan for module packages
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,
    },

    /// Search available modules from the InnerWarden registry
    ///
    /// Fetches the live registry from the repository and lists all modules,
    /// optionally filtering by name, tag, or description.
    ///
    /// Examples:
    ///   innerwarden module search
    ///   innerwarden module search ssh
    ///   innerwarden module search honeypot
    Search {
        /// Filter by name, tag, or description (case-insensitive)
        query: Option<String>,
    },

    /// Install a module by name, URL, or local path
    ///
    /// Accepts:
    ///   - A module name from the registry:  innerwarden module install ssh-protection
    ///   - An HTTPS URL to a .tar.gz:        innerwarden module install https://...
    ///   - A local file or directory path:   innerwarden module install ./my-module
    ///
    /// Built-in modules are enabled directly without downloading anything.
    Install {
        /// Module name (registry), HTTPS URL, or local path to a .tar.gz / directory
        source: String,

        /// Directory where modules are installed
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,

        /// Enable the module immediately after installing
        #[arg(long)]
        enable: bool,

        /// Overwrite if the module ID is already installed
        #[arg(long)]
        force: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Remove an installed module (disables it first if needed)
    Uninstall {
        /// Module ID to remove
        id: String,

        /// Directory where modules are installed
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Package a module directory into a distributable .tar.gz
    Publish {
        /// Path to the module directory
        path: PathBuf,

        /// Output file (defaults to <id>-v<version>.tar.gz in current directory)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Check installed modules for updates and apply them
    UpdateAll {
        /// Directory where modules are installed
        #[arg(long, default_value = "/etc/innerwarden/modules")]
        modules_dir: PathBuf,

        /// Only report available updates without installing
        #[arg(long)]
        check: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    let registry = CapabilityRegistry::default_all();

    match cli.command {
        Command::Doctor => cmd_doctor(&cli, &registry),
        Command::Upgrade {
            check,
            yes,
            ref install_dir,
        } => cmd_upgrade(&cli, check, yes, install_dir),
        Command::List => cmd_list(&cli, &registry),
        Command::Status {
            ref capability,
            ref modules_dir,
        } => match capability {
            Some(ref id) => cmd_status(&cli, &registry, id),
            None => cmd_status_global(&cli, &registry, modules_dir),
        },
        Command::Enable {
            ref capability,
            ref params,
            yes,
        } => {
            let params = parse_params(params)?;
            cmd_enable(&cli, &registry, capability, params, yes)
        }
        Command::Disable {
            ref capability,
            yes,
        } => cmd_disable(&cli, &registry, capability, yes),
        Command::Configure { ref command } => match command {
            ConfigureCommand::Ai {
                ref provider,
                ref key,
                ref model,
                ref base_url,
            } => cmd_configure_ai(
                &cli,
                provider,
                key.as_deref(),
                model.as_deref(),
                base_url.as_deref(),
            ),
            ConfigureCommand::Responder {
                enable,
                disable,
                dry_run,
            } => cmd_configure_responder(&cli, *enable, *disable, *dry_run),
        },
        Command::Module { ref command } => match command {
            ModuleCommand::Validate { ref path, strict } => cmd_module_validate(path, *strict),
            ModuleCommand::Enable { ref path, yes } => cmd_module_enable(&cli, path, *yes),
            ModuleCommand::Disable { ref path, yes } => cmd_module_disable(&cli, path, *yes),
            ModuleCommand::Search { ref query } => cmd_module_search(query.as_deref()),
            ModuleCommand::List { ref modules_dir } => cmd_module_list(&cli, modules_dir),
            ModuleCommand::Status {
                ref id,
                ref modules_dir,
            } => cmd_module_status(&cli, id, modules_dir),
            ModuleCommand::Install {
                ref source,
                ref modules_dir,
                enable,
                force,
                yes,
            } => cmd_module_install(&cli, source, modules_dir, *enable, *force, *yes),
            ModuleCommand::Uninstall {
                ref id,
                ref modules_dir,
                yes,
            } => cmd_module_uninstall(&cli, id, modules_dir, *yes),
            ModuleCommand::Publish {
                ref path,
                ref output,
            } => cmd_module_publish(path, output.as_deref()),
            ModuleCommand::UpdateAll {
                ref modules_dir,
                check,
                yes,
            } => cmd_module_update_all(&cli, modules_dir, *check, *yes),
        },
        Command::Ai { ref command } => match command {
            AiCommand::Install {
                ref model,
                ref api_key,
                yes,
            } => cmd_ai_install(&cli, model, api_key.as_deref(), *yes),
        },
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

fn cmd_list(cli: &Cli, registry: &CapabilityRegistry) -> Result<()> {
    println!("{:<20} {:<10} Description", "Capability", "Status");
    println!("{}", "─".repeat(72));
    for cap in registry.all() {
        let opts = make_opts(cli, HashMap::new(), false);
        let status = if cap.is_enabled(&opts) {
            "enabled"
        } else {
            "disabled"
        };
        println!("{:<20} {:<10} {}", cap.id(), status, cap.description());
    }
    Ok(())
}

fn cmd_status(cli: &Cli, registry: &CapabilityRegistry, id: &str) -> Result<()> {
    let cap = registry.get(id).ok_or_else(|| unknown_cap_error(id))?;
    let opts = make_opts(cli, HashMap::new(), false);
    let status = if cap.is_enabled(&opts) {
        "enabled"
    } else {
        "disabled"
    };
    println!("Capability:  {}", cap.name());
    println!("ID:          {}", cap.id());
    println!("Status:      {status}");
    println!("Description: {}", cap.description());
    Ok(())
}

fn cmd_status_global(
    cli: &Cli,
    registry: &CapabilityRegistry,
    modules_dir: &std::path::Path,
) -> Result<()> {
    use module_manifest::{is_module_enabled, scan_modules_dir};

    println!("InnerWarden Status");
    println!("{}", "═".repeat(48));

    // ── Services ─────────────────────────────────────────
    println!("\nServices");
    for unit in &["innerwarden-sensor", "innerwarden-agent"] {
        let active = systemd::is_service_active(unit);
        let indicator = if active { "●" } else { "○" };
        let label = if active { "running" } else { "stopped" };
        println!("  {indicator} {unit:<28} {label}");
    }

    // ── Capabilities ──────────────────────────────────────
    println!("\nCapabilities");
    let opts = make_opts(cli, HashMap::new(), false);
    for cap in registry.all() {
        let enabled = cap.is_enabled(&opts);
        let indicator = if enabled { "●" } else { "○" };
        let label = if enabled { "enabled " } else { "disabled" };
        println!(
            "  {indicator} {:<20} {}  {}",
            cap.id(),
            label,
            cap.description()
        );
    }

    // ── Modules ───────────────────────────────────────────
    println!("\nModules  ({})", modules_dir.display());
    let modules = scan_modules_dir(modules_dir);
    if modules.is_empty() {
        println!("  (none installed)");
    } else {
        for m in &modules {
            let enabled = is_module_enabled(&cli.sensor_config, m);
            let indicator = if enabled { "●" } else { "○" };
            let label = if enabled { "enabled " } else { "disabled" };
            println!("  {indicator} {:<20} {}  {}", m.id, label, m.name);
        }
    }

    println!();
    Ok(())
}

fn cmd_enable(
    cli: &Cli,
    registry: &CapabilityRegistry,
    id: &str,
    params: HashMap<String, String>,
    yes: bool,
) -> Result<()> {
    let cap = registry.get(id).ok_or_else(|| unknown_cap_error(id))?;
    let opts = make_opts(cli, params, yes);

    if cap.is_enabled(&opts) {
        println!(
            "Capability '{}' is already enabled. Nothing to do.",
            cap.id()
        );
        return Ok(());
    }

    println!("Enabling capability: {}\n", cap.name());

    // --- Preflight checks ---
    println!("Preflight checks:");
    let preflights = cap.preflights(&opts);
    let mut any_failed = false;
    for pf in &preflights {
        match pf.check() {
            Ok(()) => println!("  [ok] {}", pf.name()),
            Err(e) => {
                println!("  [fail] {}", e.message);
                if let Some(hint) = &e.fix_hint {
                    println!("         → {hint}");
                }
                any_failed = true;
            }
        }
    }
    if any_failed {
        anyhow::bail!("preflight checks failed — no changes applied");
    }

    // --- Planned effects ---
    println!("\nPlanned changes:");
    let effects = cap.planned_effects(&opts);
    for (i, effect) in effects.iter().enumerate() {
        println!("  {}. {}", i + 1, effect.description);
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    // --- Confirmation ---
    if !yes {
        print!("\nApply? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    // --- Activate ---
    let report = cap.activate(&opts)?;
    for effect in &report.effects_applied {
        println!("  [done] {}", effect.description);
    }
    for warn in &report.warnings {
        println!("  [warn] {warn}");
    }

    println!("\nCapability '{}' is now enabled.", cap.id());
    Ok(())
}

fn cmd_module_validate(path: &std::path::Path, strict: bool) -> Result<()> {
    let report = module_validator::validate(path, strict)?;
    report.print();
    if report.passed() {
        Ok(())
    } else {
        anyhow::bail!("module validation failed")
    }
}

fn cmd_module_enable(cli: &Cli, path: &std::path::Path, yes: bool) -> Result<()> {
    use module_manifest::{
        generate_module_sudoers_rule, is_module_enabled, module_planned_effects, ModuleManifest,
    };

    // 1. Validate manifest before touching anything
    let report = module_validator::validate(path, false)?;
    if !report.passed() {
        report.print();
        anyhow::bail!("module validation failed — fix errors before enabling");
    }

    // 2. Parse manifest
    let manifest = ModuleManifest::from_path(path)?;

    println!("Enabling module: {} ({})\n", manifest.name, manifest.id);

    // 3. Check if already enabled
    if is_module_enabled(&cli.sensor_config, &manifest) {
        println!(
            "Module '{}' is already enabled. Nothing to do.",
            manifest.id
        );
        return Ok(());
    }

    // 4. Preflight checks
    println!("Preflight checks:");
    let mut any_failed = false;
    for pf in &manifest.preflights {
        let (ok, err_msg) = run_module_preflight(pf);
        if ok {
            println!("  [ok]   {}", pf.reason);
        } else {
            println!("  [fail] {} — {}", pf.reason, err_msg);
            any_failed = true;
        }
    }
    if manifest.preflights.is_empty() {
        println!("  (none required)");
    }
    if any_failed {
        anyhow::bail!("preflight checks failed — no changes applied");
    }

    // 5. Planned effects
    let effects = module_planned_effects(&cli.sensor_config, &cli.agent_config, &manifest);
    println!("\nPlanned changes:");
    for (i, e) in effects.iter().enumerate() {
        println!("  {}. {}", i + 1, e);
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    // 6. Confirmation
    if !yes {
        print!("\nApply? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    // 7. Apply
    apply_module_enable(cli, &manifest, &generate_module_sudoers_rule)?;

    println!("\nModule '{}' is now enabled.", manifest.id);
    Ok(())
}

fn cmd_module_disable(cli: &Cli, path: &std::path::Path, yes: bool) -> Result<()> {
    use module_manifest::{is_module_enabled, module_disable_effects, ModuleManifest};

    let manifest = ModuleManifest::from_path(path)?;

    println!("Disabling module: {} ({})\n", manifest.name, manifest.id);

    if !is_module_enabled(&cli.sensor_config, &manifest) {
        println!("Module '{}' is not enabled. Nothing to do.", manifest.id);
        return Ok(());
    }

    let effects = module_disable_effects(&cli.sensor_config, &cli.agent_config, &manifest);
    println!("Changes to apply:");
    for (i, e) in effects.iter().enumerate() {
        println!("  {}. {}", i + 1, e);
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nApply? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();
    apply_module_disable(cli, &manifest)?;
    println!("\nModule '{}' is now disabled.", manifest.id);
    Ok(())
}

fn cmd_module_list(cli: &Cli, modules_dir: &std::path::Path) -> Result<()> {
    use module_manifest::{is_module_enabled, scan_modules_dir};

    let modules = scan_modules_dir(modules_dir);

    if modules.is_empty() {
        println!("No modules found in {}", modules_dir.display());
        println!("Use 'innerwarden module enable <path>' to enable a module from its directory.");
        return Ok(());
    }

    println!(
        "{:<24} {:<10} {:<8} Description",
        "Module", "Status", "Tier"
    );
    println!("{}", "─".repeat(80));

    for m in &modules {
        let status = if is_module_enabled(&cli.sensor_config, m) {
            "enabled"
        } else {
            "disabled"
        };
        // Truncate description to keep table readable
        let desc: String = m.name.chars().take(23).collect();
        println!("{:<24} {:<10} {:<8} {}", m.id, status, "open", desc);
    }
    Ok(())
}

fn cmd_module_status(cli: &Cli, id: &str, modules_dir: &std::path::Path) -> Result<()> {
    use module_manifest::{
        collector_section, detector_section, is_module_enabled, scan_modules_dir,
    };

    let modules = scan_modules_dir(modules_dir);
    let manifest = modules.iter().find(|m| m.id == id).ok_or_else(|| {
        anyhow::anyhow!(
            "module '{}' not found in {} — check the path or run 'innerwarden module list'",
            id,
            modules_dir.display()
        )
    })?;

    let enabled = is_module_enabled(&cli.sensor_config, manifest);
    let status = if enabled { "enabled" } else { "disabled" };
    let builtin = if manifest.builtin { "yes" } else { "no" };

    println!("Module:      {}", manifest.name);
    println!("ID:          {}", manifest.id);
    println!("Status:      {status}");
    println!("Builtin:     {builtin}");

    if !manifest.collectors.is_empty() {
        let parts: Vec<String> = manifest
            .collectors
            .iter()
            .map(|id| {
                let on = collector_section(id)
                    .map(|s| config_editor::read_bool(&cli.sensor_config, s, "enabled"))
                    .unwrap_or(false);
                format!("{id} ({})", if on { "enabled" } else { "disabled" })
            })
            .collect();
        println!("Collectors:  {}", parts.join(", "));
    }

    if !manifest.detectors.is_empty() {
        let parts: Vec<String> = manifest
            .detectors
            .iter()
            .map(|id| {
                let on = detector_section(id)
                    .map(|s| config_editor::read_bool(&cli.sensor_config, s, "enabled"))
                    .unwrap_or(false);
                format!("{id} ({})", if on { "enabled" } else { "disabled" })
            })
            .collect();
        println!("Detectors:   {}", parts.join(", "));
    }

    if !manifest.skills.is_empty() {
        println!("Skills:      {}", manifest.skills.join(", "));
    }

    Ok(())
}

fn apply_module_disable(cli: &Cli, manifest: &module_manifest::ModuleManifest) -> Result<()> {
    use module_manifest::{collector_section, detector_section};

    // Disable collectors
    for id in &manifest.collectors {
        if let Some(section) = collector_section(id) {
            config_editor::write_bool(&cli.sensor_config, section, "enabled", false)?;
            println!("  [done] [{section}] enabled = false");
        }
    }

    // Disable detectors
    for id in &manifest.detectors {
        if let Some(section) = detector_section(id) {
            config_editor::write_bool(&cli.sensor_config, section, "enabled", false)?;
            println!("  [done] [{section}] enabled = false");
        }
    }

    // Remove skills from allowed_skills
    for skill in &manifest.skills {
        let removed = config_editor::write_array_remove(
            &cli.agent_config,
            "responder",
            "allowed_skills",
            skill,
        )?;
        if removed {
            println!("  [done] Removed \"{skill}\" from [responder] allowed_skills");
        }
    }

    // Remove sudoers drop-in
    if !manifest.allowed_commands.is_empty() {
        let drop_in_name = format!("innerwarden-module-{}", manifest.id);
        let drop_in = sudoers::SudoersDropIn::new(drop_in_name, String::new());
        drop_in.remove(cli.dry_run)?;
        println!(
            "  [done] Removed /etc/sudoers.d/innerwarden-module-{}",
            manifest.id
        );
    }

    // Restart services
    let needs_sensor = !manifest.collectors.is_empty() || !manifest.detectors.is_empty();
    let needs_agent = !manifest.skills.is_empty();

    if needs_sensor {
        systemd::restart_service("innerwarden-sensor", cli.dry_run)?;
        println!("  [done] Restarted innerwarden-sensor");
    }
    if needs_agent {
        systemd::restart_service("innerwarden-agent", cli.dry_run)?;
        println!("  [done] Restarted innerwarden-agent");
    }

    Ok(())
}

fn run_module_preflight(pf: &module_manifest::ModulePreflightSpec) -> (bool, String) {
    match pf.kind.as_str() {
        "binary_exists" => {
            let exists = std::path::Path::new(&pf.value).exists();
            (exists, format!("{} not found", pf.value))
        }
        "directory_exists" => {
            let exists = std::path::Path::new(&pf.value).is_dir();
            (exists, format!("directory {} not found", pf.value))
        }
        "user_exists" => {
            // Check via /etc/passwd presence (no external tools needed)
            let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
            let exists = passwd
                .lines()
                .any(|l| l.split(':').next().is_some_and(|u| u == pf.value));
            (exists, format!("user '{}' does not exist", pf.value))
        }
        _ => (true, String::new()), // unknown kind = pass (fail-open)
    }
}

fn apply_module_enable(
    cli: &Cli,
    manifest: &module_manifest::ModuleManifest,
    sudoers_rule_fn: &dyn Fn(&str, &[String]) -> String,
) -> Result<()> {
    use module_manifest::{collector_section, detector_section};

    // Enable collectors in sensor config
    for id in &manifest.collectors {
        if let Some(section) = collector_section(id) {
            config_editor::write_bool(&cli.sensor_config, section, "enabled", true)?;
            println!("  [done] [{section}] enabled = true");
        } else {
            println!("  [warn] unknown collector '{id}' — no sensor config section found; skipped");
        }
    }

    // Enable detectors in sensor config
    for id in &manifest.detectors {
        if let Some(section) = detector_section(id) {
            config_editor::write_bool(&cli.sensor_config, section, "enabled", true)?;
            println!("  [done] [{section}] enabled = true");
        } else {
            println!("  [warn] unknown detector '{id}' — no sensor config section found; skipped");
        }
    }

    // Add skills to agent allowed_skills and enable responder
    if !manifest.skills.is_empty() {
        config_editor::write_bool(&cli.agent_config, "responder", "enabled", true)?;
        println!("  [done] [responder] enabled = true");
    }
    for skill in &manifest.skills {
        let added = config_editor::write_array_push(
            &cli.agent_config,
            "responder",
            "allowed_skills",
            skill,
        )?;
        if added {
            println!("  [done] Added \"{skill}\" to [responder] allowed_skills");
        }
    }

    // Install sudoers drop-in if commands are declared
    if !manifest.allowed_commands.is_empty() {
        let rule = sudoers_rule_fn(&manifest.id, &manifest.allowed_commands);
        let drop_in_name = format!("innerwarden-module-{}", manifest.id);
        let drop_in = sudoers::SudoersDropIn::new(drop_in_name, rule);
        drop_in.install(cli.dry_run)?;
        println!(
            "  [done] Wrote /etc/sudoers.d/innerwarden-module-{}",
            manifest.id
        );
    }

    // Restart services
    let needs_sensor = !manifest.collectors.is_empty() || !manifest.detectors.is_empty();
    let needs_agent = !manifest.skills.is_empty();

    if needs_sensor {
        systemd::restart_service("innerwarden-sensor", cli.dry_run)?;
        println!("  [done] Restarted innerwarden-sensor");
    }
    if needs_agent {
        systemd::restart_service("innerwarden-agent", cli.dry_run)?;
        println!("  [done] Restarted innerwarden-agent");
    }

    Ok(())
}

fn cmd_disable(cli: &Cli, registry: &CapabilityRegistry, id: &str, yes: bool) -> Result<()> {
    let cap = registry.get(id).ok_or_else(|| unknown_cap_error(id))?;
    let opts = make_opts(cli, HashMap::new(), yes);

    if !cap.is_enabled(&opts) {
        println!("Capability '{}' is not enabled. Nothing to do.", cap.id());
        return Ok(());
    }

    println!("Disabling capability: {}\n", cap.name());

    println!("Changes to apply:");
    let effects = cap.planned_disable_effects(&opts);
    for (i, effect) in effects.iter().enumerate() {
        println!("  {}. {}", i + 1, effect.description);
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nApply? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    let report = cap.deactivate(&opts)?;
    for effect in &report.effects_applied {
        println!("  [done] {}", effect.description);
    }
    for warn in &report.warnings {
        println!("  [warn] {warn}");
    }

    println!("\nCapability '{}' is now disabled.", cap.id());
    Ok(())
}

// ---------------------------------------------------------------------------
// Registry — fetched from GitHub raw content at install/search time
// ---------------------------------------------------------------------------

const REGISTRY_URL: &str =
    "https://raw.githubusercontent.com/maiconburn/innerwarden/main/registry.toml";

/// A single entry from registry.toml.
#[derive(Debug)]
struct RegistryModule {
    id: String,
    name: String,
    version: String,
    description: String,
    tags: Vec<String>,
    tier: String,
    builtin: bool,
    /// Capabilities to activate for builtin modules (maps to `innerwarden enable <cap>`)
    enables: Vec<String>,
    /// Tarball URL for non-builtin modules
    install_url: Option<String>,
}

/// Fetch and parse the registry. Falls back to an empty list on network errors
/// so `module install <url>` still works offline.
fn fetch_registry() -> Vec<RegistryModule> {
    let raw = match ureq_get(REGISTRY_URL) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [warn] could not fetch registry: {e}");
            return vec![];
        }
    };

    parse_registry_toml(&raw)
}

fn parse_registry_toml(raw: &str) -> Vec<RegistryModule> {
    // Minimal TOML array-of-tables parser — no external dep needed.
    // We parse [[modules]] blocks by splitting on that header.
    let mut modules = vec![];
    for block in raw.split("\n[[modules]]") {
        let get = |key: &str| -> String {
            for line in block.lines() {
                let line = line.trim();
                if line.starts_with(&format!("{key} ")) || line.starts_with(&format!("{key}=")) {
                    if let Some(rest) = line.splitn(2, '=').nth(1) {
                        return rest.trim().trim_matches('"').to_string();
                    }
                }
            }
            String::new()
        };
        let get_bool = |key: &str| get(key) == "true";
        let get_vec = |key: &str| -> Vec<String> {
            for line in block.lines() {
                let line = line.trim();
                if line.starts_with(&format!("{key} ")) || line.starts_with(&format!("{key}=")) {
                    if let Some(rest) = line.splitn(2, '=').nth(1) {
                        return rest
                            .trim()
                            .trim_start_matches('[')
                            .trim_end_matches(']')
                            .split(',')
                            .map(|s| s.trim().trim_matches('"').to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                }
            }
            vec![]
        };

        let id = get("id");
        if id.is_empty() {
            continue;
        }
        modules.push(RegistryModule {
            id,
            name: get("name"),
            version: get("version"),
            description: get("description"),
            tags: get_vec("tags"),
            tier: get("tier"),
            builtin: get_bool("builtin"),
            enables: get_vec("enables"),
            install_url: {
                let u = get("install_url");
                if u.is_empty() { None } else { Some(u) }
            },
        });
    }
    modules
}

/// Simple blocking HTTP GET — downloads URL to a temp file and reads it.
fn ureq_get(url: &str) -> anyhow::Result<String> {
    use std::io::Read;
    let tmp = tempfile::tempdir()?;
    let dest = module_package::download(url, tmp.path())?;
    let mut s = String::new();
    std::fs::File::open(dest)?.read_to_string(&mut s)?;
    Ok(s)
}

// ---------------------------------------------------------------------------
// innerwarden module search
// ---------------------------------------------------------------------------

fn cmd_module_search(query: Option<&str>) -> Result<()> {
    println!("Fetching registry from {}...", REGISTRY_URL);
    let modules = fetch_registry();

    if modules.is_empty() {
        println!("No modules found (registry unavailable or empty).");
        return Ok(());
    }

    let q = query.unwrap_or("").to_lowercase();
    let filtered: Vec<_> = modules
        .iter()
        .filter(|m| {
            q.is_empty()
                || m.id.contains(&q)
                || m.name.to_lowercase().contains(&q)
                || m.description.to_lowercase().contains(&q)
                || m.tags.iter().any(|t| t.to_lowercase().contains(&q))
        })
        .collect();

    if filtered.is_empty() {
        println!("No modules match '{q}'.");
        return Ok(());
    }

    println!();
    for m in &filtered {
        let tier_badge = if m.tier == "premium" { " [premium]" } else { "" };
        let builtin_note = if m.builtin { " (built-in)" } else { "" };
        println!("  {}  v{}{}{}", m.id, m.version, tier_badge, builtin_note);
        println!("    {}", m.description);
        if !m.tags.is_empty() {
            println!("    tags: {}", m.tags.join(", "));
        }
        println!();
    }

    println!("{} module(s) found.", filtered.len());
    if query.is_none() {
        println!("Install: innerwarden module install <id>");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Module install / uninstall / publish
// ---------------------------------------------------------------------------

fn cmd_module_install(
    cli: &Cli,
    source: &str,
    modules_dir: &Path,
    enable_after: bool,
    force: bool,
    yes: bool,
) -> Result<()> {
    use module_manifest::ModuleManifest;
    use module_package::*;

    let is_url = source.starts_with("https://") || source.starts_with("http://");
    let is_path = source.starts_with('/') || source.starts_with('.') || std::path::Path::new(source).exists();

    // ── Registry lookup: short module name (e.g. "ssh-protection") ────────
    if !is_url && !is_path {
        let name = source;
        println!("Looking up '{}' in the InnerWarden registry...", name);
        let registry = fetch_registry();
        let entry = registry
            .into_iter()
            .find(|m| m.id == name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Module '{}' not found in registry.\n\
                     Run 'innerwarden module search' to see available modules.\n\
                     You can also pass a URL or local path directly.",
                    name
                )
            })?;

        println!("Found: {} v{} — {}", entry.name, entry.version, entry.description);
        println!();

        // Built-in modules ship with the binary; enable the underlying capabilities.
        if entry.builtin {
            if entry.enables.is_empty() {
                println!("'{}' is a built-in module configured via sensor config.", entry.id);
                println!("See modules/{}/docs/README.md for setup instructions.", entry.id);
                return Ok(());
            }
            println!("'{}' is a built-in module. Enabling its capabilities:", entry.id);
            for cap in &entry.enables {
                println!("  innerwarden enable {cap}");
            }
            println!();
            if !yes {
                print!("Proceed? [Y/n] ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                let trimmed = input.trim().to_lowercase();
                if !trimmed.is_empty() && trimmed != "y" {
                    println!("Aborted.");
                    return Ok(());
                }
            }
            let cap_registry = CapabilityRegistry::default_all();
            for cap_id in &entry.enables {
                if cap_registry.get(cap_id).is_none() {
                    anyhow::bail!("capability '{}' not found — update InnerWarden", cap_id);
                }
                cmd_enable(cli, &cap_registry, cap_id, HashMap::new(), yes)?;
            }
            return Ok(());
        }

        // External module — install from registry URL.
        let url = entry.install_url.ok_or_else(|| {
            anyhow::anyhow!("Registry entry for '{}' has no install_url", name)
        })?;
        println!("Downloading from registry...");
        return cmd_module_install(cli, &url, modules_dir, enable_after, force, yes);
    }

    let tmp = tempfile::tempdir().context("failed to create temp directory")?;

    // ── Download or resolve local path ────────────────────────────────────
    let tarball_path: PathBuf = if is_url {
        println!("Downloading module package...");
        let path = download(source, tmp.path())?;

        // Verify SHA-256 sidecar if available
        if let Some(expected) = fetch_sha256_sidecar(source) {
            print!("  Validating SHA-256... ");
            std::io::stdout().flush()?;
            verify_sha256(&path, &expected)?;
            println!("ok");
        } else {
            println!("  (no SHA-256 sidecar found — skipping integrity check)");
        }
        path
    } else {
        let p = PathBuf::from(source);
        if !p.exists() {
            anyhow::bail!("local path not found: {}", p.display());
        }
        // Check for local sidecar
        let sidecar = PathBuf::from(format!("{}.sha256", source));
        if sidecar.exists() {
            let expected = std::fs::read_to_string(&sidecar)?;
            verify_sha256(&p, expected.split_whitespace().next().unwrap_or(""))?;
            println!("  SHA-256 ok");
        }
        p
    };

    // ── Extract ───────────────────────────────────────────────────────────
    let extract_dir = tmp.path().join("extracted");
    std::fs::create_dir_all(&extract_dir)?;
    extract_tarball(&tarball_path, &extract_dir)?;
    let module_dir = find_module_dir(&extract_dir)?;

    // ── Validate manifest ─────────────────────────────────────────────────
    let report = module_validator::validate(&module_dir, false)?;
    if !report.passed() {
        report.print();
        anyhow::bail!("module validation failed — package is not installable");
    }

    let manifest = ModuleManifest::from_path(&module_dir)?;
    println!("Module: {} ({})", manifest.name, manifest.id);

    // ── Check existing installation ───────────────────────────────────────
    let install_dest = modules_dir.join(&manifest.id);
    if install_dest.exists() {
        if !force {
            anyhow::bail!(
                "module '{}' is already installed in {}\n\
                 Use --force to overwrite.",
                manifest.id,
                modules_dir.display()
            );
        }
        println!("  (overwriting existing installation)");
    }

    // ── Plan ──────────────────────────────────────────────────────────────
    println!("\nWill install to: {}", install_dest.display());
    if enable_after {
        println!("Will enable after install.");
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nInstall? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    // ── Copy to modules_dir/<id>/ ─────────────────────────────────────────
    std::fs::create_dir_all(modules_dir)
        .with_context(|| format!("cannot create {}", modules_dir.display()))?;
    if install_dest.exists() {
        std::fs::remove_dir_all(&install_dest)?;
    }
    copy_dir(&module_dir, &install_dest)?;
    println!("  [done] Installed → {}", install_dest.display());

    // ── Enable immediately if requested ───────────────────────────────────
    if enable_after {
        println!();
        cmd_module_enable(cli, &install_dest, yes)?;
    } else {
        println!(
            "\nModule '{}' installed. Run 'innerwarden module enable {}' to activate.",
            manifest.id,
            install_dest.display()
        );
    }
    Ok(())
}

fn cmd_module_uninstall(cli: &Cli, id: &str, modules_dir: &Path, yes: bool) -> Result<()> {
    use module_manifest::{is_module_enabled, ModuleManifest};

    let install_dir = modules_dir.join(id);
    if !install_dir.exists() {
        anyhow::bail!(
            "module '{}' is not installed in {}",
            id,
            modules_dir.display()
        );
    }

    let manifest = ModuleManifest::from_path(&install_dir)?;
    println!("Uninstalling module: {} ({})", manifest.name, manifest.id);

    // Disable first if enabled
    let enabled = is_module_enabled(&cli.sensor_config, &manifest);
    if enabled {
        println!("  Module is currently enabled — will disable before removing.");
    }

    println!("  Will remove: {}", install_dir.display());

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nUninstall? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    if enabled {
        apply_module_disable(cli, &manifest)?;
    }

    std::fs::remove_dir_all(&install_dir)
        .with_context(|| format!("failed to remove {}", install_dir.display()))?;
    println!("  [done] Removed {}", install_dir.display());
    println!("\nModule '{}' uninstalled.", manifest.id);
    Ok(())
}

fn cmd_module_publish(module_path: &Path, output: Option<&Path>) -> Result<()> {
    use module_manifest::ModuleManifest;
    use module_package::*;

    // Validate before packaging
    let report = module_validator::validate(module_path, false)?;
    if !report.passed() {
        report.print();
        anyhow::bail!("module validation failed — fix errors before publishing");
    }

    let manifest = ModuleManifest::from_path(module_path)?;

    // Determine output path: <id>-v<version>.tar.gz or caller-supplied
    let tarball_path = if let Some(p) = output {
        p.to_path_buf()
    } else {
        let version = manifest.version.as_deref().unwrap_or("0.1.0");
        PathBuf::from(format!("{}-v{version}.tar.gz", manifest.id))
    };

    println!("Publishing module: {} ({})", manifest.name, manifest.id);
    println!("  Output: {}", tarball_path.display());

    create_tarball(module_path, &tarball_path)?;
    println!("  [done] Created {}", tarball_path.display());

    let sidecar = write_sha256_sidecar(&tarball_path)?;
    let hex = sha256_hex(&tarball_path)?;
    println!("  [done] SHA-256:  {hex}");
    println!("  [done] Sidecar:  {}", sidecar.display());

    println!(
        "\nInstall with:\n  innerwarden module install {}",
        tarball_path.display()
    );
    Ok(())
}

fn cmd_module_update_all(cli: &Cli, modules_dir: &Path, check_only: bool, yes: bool) -> Result<()> {
    use module_manifest::{scan_modules_dir, ModuleManifest};
    use module_package::*;
    use upgrade::is_newer;

    let modules = scan_modules_dir(modules_dir);
    if modules.is_empty() {
        println!("No modules installed in {}.", modules_dir.display());
        return Ok(());
    }

    println!("Checking modules for updates...\n");

    struct UpdateCandidate {
        manifest: ModuleManifest,
        current_version: String,
        new_version: String,
        url: String,
    }

    let mut candidates: Vec<UpdateCandidate> = Vec::new();
    let mut skipped = 0usize;

    for manifest in &modules {
        let current = manifest.version.as_deref().unwrap_or("0.0.0");

        let Some(ref url) = manifest.update_url else {
            println!("  {:<24} (no update_url — skipped)", manifest.id);
            skipped += 1;
            continue;
        };

        // Download to temp, extract, read new version
        let tmp = tempfile::tempdir().context("failed to create temp dir")?;
        print!("  {:<24} checking... ", manifest.id);
        std::io::stdout().flush()?;

        let tarball = match download(url, tmp.path()) {
            Ok(p) => p,
            Err(e) => {
                println!("error ({})", e);
                continue;
            }
        };

        // Validate SHA-256 sidecar if available
        if let Some(expected) = fetch_sha256_sidecar(url) {
            if let Err(e) = verify_sha256(&tarball, &expected) {
                println!("SHA-256 mismatch — skipping ({})", e);
                continue;
            }
        }

        let extract_dir = tmp.path().join("extracted");
        std::fs::create_dir_all(&extract_dir)?;
        if let Err(e) = extract_tarball(&tarball, &extract_dir) {
            println!("extract error — skipping ({})", e);
            continue;
        }
        let module_dir = match find_module_dir(&extract_dir) {
            Ok(d) => d,
            Err(e) => {
                println!("no module.toml — skipping ({})", e);
                continue;
            }
        };
        let new_manifest = match ModuleManifest::from_path(&module_dir) {
            Ok(m) => m,
            Err(e) => {
                println!("manifest parse error — skipping ({})", e);
                continue;
            }
        };
        let new_version = new_manifest
            .version
            .as_deref()
            .unwrap_or("0.0.0")
            .to_string();

        if is_newer(current, &new_version) {
            println!("{current} → {new_version}  [update available]");
            candidates.push(UpdateCandidate {
                manifest: manifest.clone(),
                current_version: current.to_string(),
                new_version,
                url: url.clone(),
            });
        } else {
            println!("{current}  [up to date]");
        }
    }

    println!();

    if candidates.is_empty() {
        println!("All modules are up to date.");
        return Ok(());
    }

    println!("{} update(s) available:", candidates.len());
    for c in &candidates {
        println!(
            "  {} {} → {}",
            c.manifest.id, c.current_version, c.new_version
        );
    }

    if check_only {
        println!("\nRun 'innerwarden module update-all' to install.");
        return Ok(());
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nApply {} update(s)? [Y/n] ", candidates.len());
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();
    let mut updated = 0usize;
    for c in &candidates {
        println!(
            "Updating {} ({} → {})...",
            c.manifest.id, c.current_version, c.new_version
        );
        let install_dir = modules_dir.join(&c.manifest.id);
        match cmd_module_install(cli, &c.url, modules_dir, false, true, true) {
            Ok(()) => {
                println!("  [done] {} updated to {}", c.manifest.id, c.new_version);
                // Re-enable if it was enabled before
                if module_manifest::is_module_enabled(&cli.sensor_config, &c.manifest) {
                    let _ = cmd_module_enable(cli, &install_dir, true);
                }
                updated += 1;
            }
            Err(e) => println!("  [fail] {}: {}", c.manifest.id, e),
        }
    }

    println!(
        "\n{updated}/{} module(s) updated successfully.",
        candidates.len()
    );
    if skipped > 0 {
        println!("({skipped} skipped — no update_url declared)");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// C.5 — Upgrade
// ---------------------------------------------------------------------------

fn cmd_upgrade(cli: &Cli, check_only: bool, yes: bool, install_dir: &Path) -> Result<()> {
    use upgrade::*;

    println!("Checking for updates...");

    let release =
        fetch_latest_release().context("could not reach GitHub — check network and try again")?;

    let current = CURRENT_VERSION;
    let latest = strip_v(&release.tag_name);

    println!("  Current version:  {current}");

    if !is_newer(current, &release.tag_name) {
        println!("  Latest release:   {latest} — already up to date.");
        return Ok(());
    }

    println!("  Latest release:   {latest}  ({})", release.html_url);

    if check_only {
        println!("\nRun 'innerwarden upgrade' to install.");
        return Ok(());
    }

    // Detect architecture
    let arch = detect_arch().ok_or_else(|| {
        anyhow::anyhow!(
            "unsupported CPU architecture '{}' — build from source for your platform",
            std::env::consts::ARCH
        )
    })?;

    // Build download plan
    let plan = build_plan(&release, arch);

    if plan.is_empty() {
        anyhow::bail!(
            "no assets found for linux-{arch} in release {} — \
             check {} for manual download",
            release.tag_name,
            release.html_url
        );
    }

    println!("\nAssets available for linux-{arch}:");
    for dp in &plan {
        let sha_status = if dp.sha256_asset.is_some() {
            "sha256 ✓"
        } else {
            "no sha256"
        };
        println!(
            "  {:<28} {}  ({})",
            dp.target.binary,
            fmt_bytes(dp.asset.size),
            sha_status
        );
    }

    let dest_paths: Vec<_> = plan
        .iter()
        .flat_map(|dp| install_paths(dp.target, install_dir))
        .collect();

    println!("\nWill install to {}:", install_dir.display());
    for p in &dest_paths {
        println!("  {}", p.display());
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nProceed? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    let tmp_dir = tempfile::tempdir().context("failed to create temp directory")?;

    for dp in &plan {
        let binary = dp.target.binary;
        print!("  Downloading {binary}... ");
        std::io::stdout().flush()?;

        let tmp_path = tmp_dir.path().join(binary);
        let bytes = download(&dp.asset.browser_download_url, &tmp_path)?;

        // Verify SHA-256 if sidecar is present
        if let Some(sha_asset) = dp.sha256_asset {
            let expected = fetch_expected_hash(&sha_asset.browser_download_url)?;
            let actual = sha256_file(&tmp_path)?;
            if actual != expected {
                anyhow::bail!(
                    "SHA-256 mismatch for {binary}:\n  expected {expected}\n  got      {actual}"
                );
            }
            println!("{}  sha256 ok", fmt_bytes(bytes));
        } else {
            println!("{}  (no sha256 sidecar)", fmt_bytes(bytes));
        }

        // Install to all target names
        for dest in install_paths(dp.target, install_dir) {
            install_binary(&tmp_path, &dest, false)?;
            println!("  [done] {} → {}", binary, dest.display());
        }
    }

    // Restart running services
    println!();
    for unit in &["innerwarden-sensor", "innerwarden-agent"] {
        if systemd::is_service_active(unit) {
            systemd::restart_service(unit, false)?;
            println!("  [done] Restarted {unit}");
        }
    }

    println!(
        "\nInnerWarden upgraded to {} successfully.",
        release.tag_name
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Configure AI
// ---------------------------------------------------------------------------

fn write_env_key(env_path: &Path, key: &str, value: &str) -> Result<()> {
    let existing = std::fs::read_to_string(env_path).unwrap_or_default();
    let mut lines: Vec<String> = existing
        .lines()
        .filter(|l| {
            // Remove existing setting (active or commented)
            let l = l.trim_start_matches('#').trim_start();
            !l.starts_with(&format!("{key}="))
        })
        .map(|l| l.to_string())
        .collect();
    lines.push(format!("{key}={value}"));
    let new_content = lines.join("\n") + "\n";
    // Atomic write via temp file in same directory
    let tmp = env_path.with_extension("env.tmp");
    std::fs::write(&tmp, &new_content)
        .with_context(|| format!("cannot write {}", tmp.display()))?;
    std::fs::rename(&tmp, env_path)
        .with_context(|| format!("cannot update {}", env_path.display()))?;
    Ok(())
}

fn cmd_configure_ai(
    cli: &Cli,
    provider: &str,
    key: Option<&str>,
    model: Option<&str>,
    base_url: Option<&str>,
) -> Result<()> {
    let (default_model, key_var): (&str, Option<&str>) = match provider {
        "openai" => ("gpt-4o-mini", Some("OPENAI_API_KEY")),
        "anthropic" => ("claude-haiku-4-5-20251001", Some("ANTHROPIC_API_KEY")),
        "ollama" => ("llama3.2", None),
        other => anyhow::bail!(
            "unknown provider '{}'\nUse one of: openai, anthropic, ollama\n\nExamples:\n  innerwarden configure ai openai --key sk-...\n  innerwarden configure ai anthropic --key sk-ant-...\n  innerwarden configure ai ollama --model llama3.2",
            other
        ),
    };

    let model = model.unwrap_or(default_model);

    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // Cloud providers require an API key
    if let Some(var) = key_var {
        let k = key.ok_or_else(|| {
            anyhow::anyhow!(
                "provider '{}' requires an API key.\nRun:\n  innerwarden configure ai {} --key <your-key>",
                provider,
                provider
            )
        })?;

        if cli.dry_run {
            println!("  [dry-run] would write {}=... to {}", var, env_file.display());
        } else {
            write_env_key(&env_file, var, k)?;
            println!("  [ok] {}=... written to {}", var, env_file.display());
        }
    }

    // Patch agent.toml
    if cli.dry_run {
        println!("  [dry-run] would set [ai] enabled=true provider={provider} model={model} in {}", cli.agent_config.display());
    } else {
        config_editor::write_bool(&cli.agent_config, "ai", "enabled", true)?;
        config_editor::write_str(&cli.agent_config, "ai", "provider", provider)?;
        config_editor::write_str(&cli.agent_config, "ai", "model", model)?;
        if provider == "ollama" {
            if let Some(url) = base_url {
                config_editor::write_str(&cli.agent_config, "ai", "base_url", url)?;
            }
        }
        println!("  [ok] agent.toml updated: provider={provider}, model={model}");
    }

    // Restart agent
    let is_macos = std::env::consts::OS == "macos";
    if cli.dry_run {
        let restart_cmd = if is_macos {
            "sudo launchctl kickstart -k system/com.innerwarden.agent"
        } else {
            "sudo systemctl restart innerwarden-agent"
        };
        println!("  [dry-run] would restart: {restart_cmd}");
    } else if is_macos {
        systemd::restart_launchd("com.innerwarden.agent", false)?;
        println!("  [ok] innerwarden-agent restarted");
    } else {
        systemd::restart_service("innerwarden-agent", false)?;
        println!("  [ok] innerwarden-agent restarted");
    }

    println!();
    println!("AI configured. Run 'innerwarden doctor' to validate.");
    Ok(())
}

fn cmd_configure_responder(
    cli: &Cli,
    enable: bool,
    disable: bool,
    dry_run_flag: Option<bool>,
) -> Result<()> {
    if !enable && !disable && dry_run_flag.is_none() {
        anyhow::bail!(
            "nothing to do — specify at least one flag.\n\nExamples:\n  innerwarden configure responder --enable\n  innerwarden configure responder --enable --dry-run false\n  innerwarden configure responder --disable"
        );
    }

    // Apply responder.enabled
    if enable || disable {
        let value = enable;
        if cli.dry_run {
            println!("  [dry-run] would set [responder] enabled={value} in {}", cli.agent_config.display());
        } else {
            config_editor::write_bool(&cli.agent_config, "responder", "enabled", value)?;
            println!("  [ok] responder.enabled = {value}");
        }
    }

    // Apply responder.dry_run
    if let Some(dr) = dry_run_flag {
        if cli.dry_run {
            println!("  [dry-run] would set [responder] dry_run={dr} in {}", cli.agent_config.display());
        } else {
            config_editor::write_bool(&cli.agent_config, "responder", "dry_run", dr)?;
            println!("  [ok] responder.dry_run = {dr}");
        }
    }

    // Restart agent
    let is_macos = std::env::consts::OS == "macos";
    if cli.dry_run {
        let restart_cmd = if is_macos {
            "sudo launchctl kickstart -k system/com.innerwarden.agent"
        } else {
            "sudo systemctl restart innerwarden-agent"
        };
        println!("  [dry-run] would restart: {restart_cmd}");
    } else if is_macos {
        systemd::restart_launchd("com.innerwarden.agent", false)?;
        println!("  [ok] innerwarden-agent restarted");
    } else {
        systemd::restart_service("innerwarden-agent", false)?;
        println!("  [ok] innerwarden-agent restarted");
    }

    println!();
    if enable && dry_run_flag == Some(false) {
        println!("Responder is live. Decisions will execute for real.");
    } else if disable {
        println!("Responder disabled. System observes only.");
    } else {
        println!("Responder updated. Run 'innerwarden status' to confirm.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden ai install
// ---------------------------------------------------------------------------

fn cmd_ai_install(cli: &Cli, model: &str, api_key_arg: Option<&str>, yes: bool) -> Result<()> {
    let is_macos = std::env::consts::OS == "macos";

    // Resolve API key: --api-key flag > OLLAMA_API_KEY env var > interactive prompt
    let api_key = if let Some(k) = api_key_arg {
        k.to_string()
    } else if let Ok(k) = std::env::var("OLLAMA_API_KEY") {
        if !k.is_empty() {
            k
        } else {
            prompt_ollama_api_key()?
        }
    } else {
        prompt_ollama_api_key()?
    };

    println!("InnerWarden AI — Ollama cloud setup");
    println!();
    println!("  Provider: Ollama cloud (https://api.ollama.com)");
    println!("  Model:    {model}");
    println!("  API key:  {}...", &api_key[..api_key.len().min(12)]);
    println!();

    if !yes {
        print!("Configure innerwarden-agent with these settings? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_lowercase();
        if !trimmed.is_empty() && trimmed != "y" {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Configure agent.toml and restart
    println!("[1/2] Updating innerwarden-agent config...");
    if cli.dry_run {
        println!("  [dry-run] would set [ai] enabled=true provider=ollama model={model} base_url=https://api.ollama.com api_key=<redacted>");
    } else {
        config_editor::write_bool(&cli.agent_config, "ai", "enabled", true)?;
        config_editor::write_str(&cli.agent_config, "ai", "provider", "ollama")?;
        config_editor::write_str(&cli.agent_config, "ai", "model", model)?;
        config_editor::write_str(&cli.agent_config, "ai", "base_url", "https://api.ollama.com")?;
        config_editor::write_str(&cli.agent_config, "ai", "api_key", &api_key)?;
        println!("  [ok] agent.toml updated");
    }

    println!("[2/2] Restarting innerwarden-agent...");
    if cli.dry_run {
        println!("  [dry-run] would restart innerwarden-agent");
    } else {
        if is_macos {
            systemd::restart_launchd("com.innerwarden.agent", false)?;
        } else {
            systemd::restart_service("innerwarden-agent", false)?;
        }
        println!("  [ok] innerwarden-agent restarted");
    }

    println!();
    println!("Done. Ollama cloud AI is active.");
    println!("Model:   {model}");
    println!("Tier:    Free (check https://ollama.com/pricing for limits)");
    println!();
    println!("Run 'innerwarden doctor' to validate the connection.");
    Ok(())
}

/// Prompt the user to paste their Ollama API key interactively.
fn prompt_ollama_api_key() -> Result<String> {
    println!("Ollama API key required.");
    println!();
    println!("  1. Create a free account at https://ollama.com");
    println!("  2. Go to https://ollama.com/settings/api-keys");
    println!("  3. Click 'New API Key', copy the key, and paste it below.");
    println!();
    print!("Ollama API key: ");
    std::io::stdout().flush()?;
    let mut key = String::new();
    std::io::stdin().read_line(&mut key)?;
    let key = key.trim().to_string();
    if key.is_empty() {
        anyhow::bail!(
            "No API key provided.\n\
             You can also set the OLLAMA_API_KEY environment variable and re-run."
        );
    }
    Ok(key)
}

// C.4 — Doctor
// ---------------------------------------------------------------------------

fn cmd_doctor(cli: &Cli, registry: &CapabilityRegistry) -> Result<()> {
    #[derive(PartialEq)]
    enum Sev {
        Ok,
        Warn,
        Fail,
    }

    struct Check {
        label: String,
        sev: Sev,
        hint: Option<String>,
    }

    impl Check {
        fn ok(label: impl Into<String>) -> Self {
            Self {
                label: label.into(),
                sev: Sev::Ok,
                hint: None,
            }
        }
        fn warn(label: impl Into<String>, hint: impl Into<String>) -> Self {
            Self {
                label: label.into(),
                sev: Sev::Warn,
                hint: Some(hint.into()),
            }
        }
        fn fail(label: impl Into<String>, hint: impl Into<String>) -> Self {
            Self {
                label: label.into(),
                sev: Sev::Fail,
                hint: Some(hint.into()),
            }
        }
        fn print(&self) {
            let tag = match self.sev {
                Sev::Ok => "[ok]  ",
                Sev::Warn => "[warn]",
                Sev::Fail => "[fail]",
            };
            println!("  {tag} {}", self.label);
            if let Some(h) = &self.hint {
                println!("         → {h}");
            }
        }
        fn is_issue(&self) -> bool {
            self.sev != Sev::Ok
        }
    }

    fn run_section(checks: Vec<Check>, issues: &mut u32) {
        for c in &checks {
            c.print();
            if c.is_issue() {
                *issues += 1;
            }
        }
    }

    println!("InnerWarden Doctor");
    println!("{}", "═".repeat(48));

    let mut total_issues: u32 = 0;

    let is_macos = std::env::consts::OS == "macos";

    // ── System ────────────────────────────────────────────
    println!("\nSystem");
    let mut sys = Vec::new();

    if is_macos {
        // launchctl
        let has_launchctl = std::path::Path::new("/bin/launchctl").exists()
            || std::path::Path::new("/usr/bin/launchctl").exists();
        sys.push(if has_launchctl {
            Check::ok("launchctl found (macOS service manager)")
        } else {
            Check::fail(
                "launchctl not found",
                "unexpected on macOS — check your PATH",
            )
        });

        // innerwarden user
        let user_ok = std::process::Command::new("id")
            .arg("innerwarden")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        sys.push(if user_ok {
            Check::ok("innerwarden system user exists")
        } else {
            Check::fail(
                "innerwarden system user missing",
                "run install.sh — it creates the user via dscl",
            )
        });

        // /etc/sudoers.d/ (exists on macOS too)
        sys.push(if std::path::Path::new("/etc/sudoers.d").is_dir() {
            Check::ok("/etc/sudoers.d/ directory exists")
        } else {
            Check::warn(
                "/etc/sudoers.d/ not found",
                "sudo mkdir -p /etc/sudoers.d  (needed for suspend-user-sudo skill)",
            )
        });

        // pfctl (needed for block-ip-pf)
        let has_pfctl = std::path::Path::new("/sbin/pfctl").exists();
        sys.push(if has_pfctl {
            Check::ok("pfctl found (block-ip-pf skill available)")
        } else {
            Check::warn(
                "pfctl not found",
                "pfctl is built-in on macOS — unexpected. block-ip-pf skill will not work.",
            )
        });

        // `log` binary (needed for macos_log collector)
        let has_log_bin = std::path::Path::new("/usr/bin/log").exists();
        sys.push(if has_log_bin {
            Check::ok("`log` binary found (macos_log collector available)")
        } else {
            Check::fail(
                "`log` binary not found at /usr/bin/log",
                "unexpected on macOS — macos_log collector requires Apple Unified Logging",
            )
        });
    } else {
        // systemctl
        let has_systemctl = std::path::Path::new("/usr/bin/systemctl").exists()
            || std::path::Path::new("/bin/systemctl").exists();
        sys.push(if has_systemctl {
            Check::ok("systemctl found")
        } else {
            Check::fail("systemctl not found", "install systemd or check PATH")
        });

        // innerwarden user
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        let user_ok = passwd
            .lines()
            .any(|l| l.split(':').next() == Some("innerwarden"));
        sys.push(if user_ok {
            Check::ok("innerwarden system user exists")
        } else {
            Check::fail(
                "innerwarden system user missing",
                "sudo useradd -r -s /sbin/nologin innerwarden",
            )
        });

        // /etc/sudoers.d/
        sys.push(if std::path::Path::new("/etc/sudoers.d").is_dir() {
            Check::ok("/etc/sudoers.d/ directory exists")
        } else {
            Check::fail("/etc/sudoers.d/ not found", "sudo mkdir -p /etc/sudoers.d")
        });
    }

    run_section(sys, &mut total_issues);

    // ── Services ──────────────────────────────────────────
    println!("\nServices");
    let mut svc = Vec::new();
    if is_macos {
        for (label, plist) in &[
            ("innerwarden-sensor", "com.innerwarden.sensor"),
            ("innerwarden-agent", "com.innerwarden.agent"),
        ] {
            let running = std::process::Command::new("launchctl")
                .args(["list", plist])
                .output()
                .map(|o| {
                    o.status.success() && String::from_utf8_lossy(&o.stdout).contains("\"PID\"")
                })
                .unwrap_or(false);
            svc.push(if running {
                Check::ok(format!("{label} is running"))
            } else {
                Check::warn(
                    format!("{label} is not running"),
                    format!("sudo launchctl load /Library/LaunchDaemons/{plist}.plist"),
                )
            });
        }
    } else {
        for unit in &["innerwarden-sensor", "innerwarden-agent"] {
            svc.push(if systemd::is_service_active(unit) {
                Check::ok(format!("{unit} is running"))
            } else {
                Check::warn(
                    format!("{unit} is not running"),
                    format!("sudo systemctl start {unit}"),
                )
            });
        }
    }
    run_section(svc, &mut total_issues);

    // ── Configuration ─────────────────────────────────────
    println!("\nConfiguration");
    let mut cfg = Vec::new();

    for (label, path) in &[("Sensor", &cli.sensor_config), ("Agent", &cli.agent_config)] {
        if path.exists() {
            cfg.push(Check::ok(format!(
                "{} config found ({})",
                label,
                path.display()
            )));
            let valid_toml = std::fs::read_to_string(path)
                .ok()
                .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
                .is_some();
            cfg.push(if valid_toml {
                Check::ok(format!("{} config is valid TOML", label))
            } else {
                Check::fail(
                    format!(
                        "{} config has invalid TOML syntax ({})",
                        label,
                        path.display()
                    ),
                    format!("fix syntax in {}", path.display()),
                )
            });
        } else {
            cfg.push(Check::fail(
                format!("{} config not found ({})", label, path.display()),
                format!("create {} — see README.md for a template", path.display()),
            ));
        }
    }

    // AI provider + API key — detect provider from agent config then validate the right key
    let env_file = cli
        .agent_config
        .parent()
        .map(|p| p.join("agent.env"))
        .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

    // Read agent.toml to find configured provider and whether AI is enabled
    let agent_doc: Option<toml_edit::DocumentMut> = cli
        .agent_config
        .exists()
        .then(|| std::fs::read_to_string(&cli.agent_config).ok())
        .flatten()
        .and_then(|s| s.parse().ok());

    let ai_enabled = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|ai| ai.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let provider = agent_doc
        .as_ref()
        .and_then(|doc| doc.get("ai"))
        .and_then(|ai| ai.get("provider"))
        .and_then(|v| v.as_str())
        .unwrap_or("openai")
        .to_string();

    // Helper: resolve a key from env var or agent.env file
    let resolve_key = |env_var: &str| -> Option<String> {
        if let Ok(v) = std::env::var(env_var) {
            if !v.trim().is_empty() {
                return Some(v);
            }
        }
        std::fs::read_to_string(&env_file).ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(&format!("{env_var}=")))
                .and_then(|l| l.split_once('=').map(|x| x.1))
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.trim().to_string())
        })
    };

    if !ai_enabled {
        cfg.push(Check::warn(
            "AI not configured (ai.enabled = false)",
            "Detection and logging still work without AI.\nTo add AI triage, run one of:\n\n  innerwarden configure ai openai --key sk-...\n  innerwarden configure ai anthropic --key sk-ant-...\n  innerwarden configure ai ollama --model llama3.2   (no key needed)",
        ));
    } else {
        match provider.as_str() {
            "anthropic" => {
                let key = resolve_key("ANTHROPIC_API_KEY");
                match &key {
                    None => {
                        cfg.push(Check::fail(
                            "ANTHROPIC_API_KEY not set (provider = \"anthropic\")",
                            "Get a key at https://console.anthropic.com/settings/keys\n\
                             Then run:\n\
                             \n  innerwarden configure ai anthropic --key sk-ant-...",
                        ));
                    }
                    Some(k) => {
                        let looks_valid = k.starts_with("sk-ant-") && k.len() >= 20;
                        cfg.push(if looks_valid {
                            Check::ok("ANTHROPIC_API_KEY is set and format looks correct")
                        } else {
                            Check::warn(
                                "ANTHROPIC_API_KEY is set but format looks wrong (should start with sk-ant-)",
                                "Run:\n  innerwarden configure ai anthropic --key sk-ant-...",
                            )
                        });
                    }
                }
            }
            "ollama" => {
                // Check if ollama is reachable
                let ollama_url = agent_doc
                    .as_ref()
                    .and_then(|doc| doc.get("ai"))
                    .and_then(|ai| ai.get("base_url"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("http://localhost:11434")
                    .to_string();
                let ollama_ok = std::process::Command::new("curl")
                    .args(["-sf", "--max-time", "2", &format!("{ollama_url}/api/tags")])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                cfg.push(if ollama_ok {
                    Check::ok(format!("Ollama reachable at {ollama_url}"))
                } else {
                    Check::fail(
                        format!("Ollama not reachable at {ollama_url}"),
                        "Install and start Ollama:\n\n  curl -fsSL https://ollama.ai/install.sh | sh\n  ollama pull llama3.2\n\nThen run: innerwarden configure ai ollama --model llama3.2",
                    )
                });
            }
            _ => {
                // Default: openai (also handles unknown providers gracefully)
                let key = resolve_key("OPENAI_API_KEY");
                match &key {
                    None => {
                        cfg.push(Check::fail(
                            "OPENAI_API_KEY not set (provider = \"openai\")",
                            "Get a key at https://platform.openai.com/api-keys\n\
                             Then run:\n\
                             \n  innerwarden configure ai openai --key sk-...",
                        ));
                    }
                    Some(k) => {
                        let looks_valid = k.starts_with("sk-") && k.len() >= 20;
                        cfg.push(if looks_valid {
                            Check::ok("OPENAI_API_KEY is set and format looks correct")
                        } else {
                            Check::warn(
                                "OPENAI_API_KEY is set but format looks wrong (should start with sk-)",
                                "Run:\n  innerwarden configure ai openai --key sk-...",
                            )
                        });
                    }
                }
            }
        }
    }

    // AbuseIPDB enrichment — only when abuseipdb.enabled = true
    {
        let abuseipdb_enabled = agent_doc
            .as_ref()
            .and_then(|doc| doc.get("abuseipdb"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if abuseipdb_enabled {
            let key_in_config = agent_doc
                .as_ref()
                .and_then(|doc| doc.get("abuseipdb"))
                .and_then(|t| t.get("api_key"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let key_in_env = std::env::var("ABUSEIPDB_API_KEY")
                .ok()
                .filter(|s| !s.is_empty());
            let key_in_file = resolve_key("ABUSEIPDB_API_KEY");
            let resolved_key = key_in_config.or(key_in_env).or(key_in_file);

            cfg.push(match &resolved_key {
                None => Check::fail(
                    "abuseipdb.enabled=true but ABUSEIPDB_API_KEY not set",
                    "1. Register at https://www.abuseipdb.com/register (free)\n\
                     2. Go to https://www.abuseipdb.com/account/api\n\
                     3. Add to agent.toml:\n\
                     \n   [abuseipdb]\n   api_key = \"<your-key>\"\n\
                     \n   Or set env var: ABUSEIPDB_API_KEY=<your-key>",
                ),
                Some(k) if k.len() < 10 => Check::warn(
                    "ABUSEIPDB_API_KEY is set but looks too short",
                    "AbuseIPDB API keys are typically 80 characters.\n\
                     Get a fresh key at https://www.abuseipdb.com/account/api",
                ),
                Some(_) => Check::ok(
                    "ABUSEIPDB_API_KEY is set (free tier: 1,000 checks/day)",
                ),
            });
        }
    }

    run_section(cfg, &mut total_issues);

    // ── Telegram ──────────────────────────────────────────
    // Only check Telegram when enabled = true in agent config.
    {
        let agent_toml: Option<toml_edit::DocumentMut> = cli
            .agent_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.agent_config).ok())
            .flatten()
            .and_then(|s| s.parse().ok());

        let telegram_enabled = agent_toml
            .as_ref()
            .and_then(|doc| doc.get("telegram"))
            .and_then(|t| t.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if telegram_enabled {
            println!("\nTelegram");
            let mut tg = Vec::new();

            let env_file_path = cli
                .agent_config
                .parent()
                .map(|p| p.join("agent.env"))
                .unwrap_or_else(|| PathBuf::from("/etc/innerwarden/agent.env"));

            // Resolve bot_token: config → env var → agent.env file
            let token_in_config = agent_toml
                .as_ref()
                .and_then(|doc| doc.get("telegram"))
                .and_then(|t| t.get("bot_token"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let token_in_env = std::env::var("TELEGRAM_BOT_TOKEN")
                .ok()
                .filter(|s| !s.is_empty());
            let token_in_file = std::fs::read_to_string(&env_file_path)
                .map(|s| {
                    s.lines()
                        .find(|l| l.starts_with("TELEGRAM_BOT_TOKEN="))
                        .and_then(|l| l.split_once('=').map(|x| x.1))
                        .filter(|v| !v.is_empty())
                        .map(|s| s.to_string())
                })
                .unwrap_or(None);
            let resolved_token = token_in_config.or(token_in_env).or(token_in_file);

            // Resolve chat_id: config → env var → agent.env file
            let chat_in_config = agent_toml
                .as_ref()
                .and_then(|doc| doc.get("telegram"))
                .and_then(|t| t.get("chat_id"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let chat_in_env = std::env::var("TELEGRAM_CHAT_ID")
                .ok()
                .filter(|s| !s.is_empty());
            let chat_in_file = std::fs::read_to_string(&env_file_path)
                .map(|s| {
                    s.lines()
                        .find(|l| l.starts_with("TELEGRAM_CHAT_ID="))
                        .and_then(|l| l.split_once('=').map(|x| x.1))
                        .filter(|v| !v.is_empty())
                        .map(|s| s.to_string())
                })
                .unwrap_or(None);
            let resolved_chat = chat_in_config.or(chat_in_env).or(chat_in_file);

            // Check bot_token presence
            match &resolved_token {
                None => {
                    tg.push(Check::fail(
                        "TELEGRAM_BOT_TOKEN not set",
                        format!(
                            "1. Open Telegram and message @BotFather\n\
                             2. Send /newbot and follow the steps\n\
                             3. Copy the token and add to {}:\n\
                             \n   TELEGRAM_BOT_TOKEN=1234567890:AABBccDDeeffGGHH...",
                            env_file_path.display()
                        ),
                    ));
                }
                Some(token) => {
                    // Validate format: <digits>:<35+ alphanumeric chars>
                    let looks_valid = token.contains(':') && {
                        let mut parts = token.splitn(2, ':');
                        let id_part = parts.next().unwrap_or("");
                        let secret_part = parts.next().unwrap_or("");
                        id_part.chars().all(|c| c.is_ascii_digit())
                            && !id_part.is_empty()
                            && secret_part.len() >= 20
                    };
                    tg.push(if looks_valid {
                        Check::ok("TELEGRAM_BOT_TOKEN is set and format looks correct")
                    } else {
                        Check::warn(
                            "TELEGRAM_BOT_TOKEN is set but format looks wrong",
                            "Token should look like: 1234567890:AABBccDDeeffGGHHiijjKK...\n\
                             Get a fresh token from @BotFather on Telegram",
                        )
                    });
                }
            }

            // Check chat_id presence
            match &resolved_chat {
                None => {
                    tg.push(Check::fail(
                        "TELEGRAM_CHAT_ID not set",
                        format!(
                            "1. Open Telegram and message @userinfobot\n\
                             2. It will reply with your chat ID (a number, e.g. 123456789)\n\
                             3. For a group/channel the ID starts with -100\n\
                             4. Add to {}:\n\
                             \n   TELEGRAM_CHAT_ID=123456789",
                            env_file_path.display()
                        ),
                    ));
                }
                Some(chat_id) => {
                    // Chat ID should be numeric (possibly negative for groups)
                    let looks_valid = chat_id
                        .trim_start_matches('-')
                        .chars()
                        .all(|c| c.is_ascii_digit())
                        && !chat_id.is_empty();
                    tg.push(if looks_valid {
                        Check::ok("TELEGRAM_CHAT_ID is set and format looks correct")
                    } else {
                        Check::warn(
                            "TELEGRAM_CHAT_ID is set but format looks wrong",
                            "Chat ID should be a number like 123456789 (personal) or -1001234567890 (group/channel)\n\
                             Message @userinfobot on Telegram to find yours",
                        )
                    });
                }
            }

            // If both token and chat_id are valid, suggest a connectivity smoke-test
            if resolved_token.is_some() && resolved_chat.is_some() {
                tg.push(Check::ok(
                    "Telegram configured — test it: innerwarden-agent --config /etc/innerwarden/agent.toml --once",
                ));
            }

            run_section(tg, &mut total_issues);
        }
    }

    // ── Capabilities ──────────────────────────────────────
    println!("\nCapabilities");
    let opts = make_opts(cli, HashMap::new(), false);
    let mut any_enabled = false;

    for cap in registry.all() {
        if !cap.is_enabled(&opts) {
            continue;
        }
        any_enabled = true;

        // Map capability → expected sudoers drop-in name
        let drop_in = match cap.id() {
            "block-ip" => Some("innerwarden-block-ip"),
            "sudo-protection" => Some("innerwarden-sudo-protection"),
            "search-protection" => Some("innerwarden-search-protection"),
            _ => None,
        };

        if let Some(name) = drop_in {
            let path = std::path::Path::new("/etc/sudoers.d").join(name);
            if path.exists() {
                println!("  [ok]   {} (enabled): sudoers drop-in present", cap.id());
            } else {
                println!(
                    "  [warn] {} (enabled): sudoers drop-in missing (/etc/sudoers.d/{name})",
                    cap.id()
                );
                println!("         → innerwarden enable {}", cap.id());
                total_issues += 1;
            }
        } else {
            println!("  [ok]   {} (enabled)", cap.id());
        }
    }

    if !any_enabled {
        println!("  (no capabilities enabled — run 'innerwarden list' to see options)");
    }

    // ── Integrations ──────────────────────────────────────
    // Only show this section when at least one integration collector is enabled.
    {
        let sensor_doc: Option<toml_edit::DocumentMut> = cli
            .sensor_config
            .exists()
            .then(|| std::fs::read_to_string(&cli.sensor_config).ok())
            .flatten()
            .and_then(|s| s.parse().ok());

        let collector_enabled = |name: &str| -> bool {
            sensor_doc
                .as_ref()
                .and_then(|doc| doc.get("collectors"))
                .and_then(|c| c.get(name))
                .and_then(|s| s.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        };

        let collector_str = |name: &str, key: &str, default: &str| -> String {
            sensor_doc
                .as_ref()
                .and_then(|doc| doc.get("collectors"))
                .and_then(|c| c.get(name))
                .and_then(|s| s.get(key))
                .and_then(|v| v.as_str())
                .unwrap_or(default)
                .to_string()
        };

        let detector_enabled = |name: &str| -> bool {
            sensor_doc
                .as_ref()
                .and_then(|doc| doc.get("detectors"))
                .and_then(|c| c.get(name))
                .and_then(|s| s.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        };

        let falco_enabled = collector_enabled("falco_log");
        let suricata_enabled = collector_enabled("suricata_eve");
        let osquery_enabled = collector_enabled("osquery_log");
        let nginx_error_enabled = collector_enabled("nginx_error");
        let any_integration =
            falco_enabled || suricata_enabled || osquery_enabled || nginx_error_enabled;

        if any_integration {
            println!("\nIntegrations");

            // ── Falco ──────────────────────────────────────
            if falco_enabled {
                println!("  Falco");
                let mut falco = Vec::new();

                let falco_binary = std::path::Path::new("/usr/bin/falco").exists()
                    || std::path::Path::new("/usr/local/bin/falco").exists();
                falco.push(if falco_binary {
                    Check::ok("Falco binary found")
                } else {
                    Check::fail(
                        "Falco binary not found (/usr/bin/falco or /usr/local/bin/falco)",
                        "sudo apt-get install falco",
                    )
                });

                let falco_active = if is_macos {
                    std::process::Command::new("launchctl")
                        .args(["list", "com.falco"])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                } else {
                    systemd::is_service_active("falco")
                        || systemd::is_service_active("falco-modern-bpf")
                };
                let falco_start_hint = if is_macos {
                    "sudo launchctl load /Library/LaunchDaemons/com.falco.plist"
                } else {
                    "sudo systemctl start falco"
                };
                falco.push(if falco_active {
                    Check::ok("Falco service is running")
                } else {
                    Check::warn("Falco service is not running", falco_start_hint)
                });

                let falco_log = collector_str("falco_log", "path", "/var/log/falco/falco.log");
                let log_ok = std::path::Path::new(&falco_log).exists()
                    && std::fs::metadata(&falco_log)
                        .map(|m| m.len() > 0)
                        .unwrap_or(false);
                let falco_restart_hint = if is_macos {
                    "sudo launchctl kickstart -k system/com.falco"
                } else {
                    "sudo mkdir -p /var/log/falco && sudo systemctl restart falco"
                };
                let falco_json_hint = if is_macos {
                    "echo 'json_output: true' | sudo tee -a /etc/falco/falco.yaml && sudo launchctl kickstart -k system/com.falco"
                } else {
                    "echo 'json_output: true' | sudo tee -a /etc/falco/falco.yaml && sudo systemctl restart falco"
                };
                falco.push(if log_ok {
                    Check::ok(format!("Falco log file exists ({})", falco_log))
                } else {
                    Check::fail(
                        format!("Falco log file not found or not readable ({})", falco_log),
                        falco_restart_hint,
                    )
                });

                let falco_yaml =
                    std::fs::read_to_string("/etc/falco/falco.yaml").unwrap_or_default();
                let json_output_ok = falco_yaml.contains("json_output: true");
                falco.push(if json_output_ok {
                    Check::ok("Falco json_output is enabled")
                } else {
                    Check::warn(
                        "Falco json_output not enabled — events will not be parseable",
                        falco_json_hint,
                    )
                });

                run_section(falco, &mut total_issues);
            }

            // ── Suricata ───────────────────────────────────
            if suricata_enabled {
                println!("  Suricata");
                let mut suri = Vec::new();

                let suri_binary = std::path::Path::new("/usr/bin/suricata").exists();
                suri.push(if suri_binary {
                    Check::ok("Suricata binary found")
                } else {
                    Check::fail(
                        "Suricata binary not found (/usr/bin/suricata)",
                        "sudo apt-get install suricata",
                    )
                });

                let suri_active = if is_macos {
                    std::process::Command::new("launchctl")
                        .args(["list", "com.suricata"])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                } else {
                    systemd::is_service_active("suricata")
                };
                let suri_start_hint = if is_macos {
                    "sudo launchctl load /Library/LaunchDaemons/com.suricata.plist"
                } else {
                    "sudo systemctl start suricata"
                };
                let suri_restart_hint = if is_macos {
                    "sudo launchctl kickstart -k system/com.suricata  # creates eve.json on first run"
                } else {
                    "sudo systemctl restart suricata  # creates eve.json on first run"
                };
                suri.push(if suri_active {
                    Check::ok("Suricata service is running")
                } else {
                    Check::warn("Suricata service is not running", suri_start_hint)
                });

                let eve_log = collector_str("suricata_eve", "path", "/var/log/suricata/eve.json");
                let eve_ok = std::path::Path::new(&eve_log).exists();
                suri.push(if eve_ok {
                    Check::ok(format!("Suricata eve.json exists ({})", eve_log))
                } else {
                    Check::fail(
                        format!("Suricata eve.json not found ({})", eve_log),
                        suri_restart_hint,
                    )
                });

                let rules_present = std::path::Path::new("/var/lib/suricata/rules/suricata.rules")
                    .exists()
                    || std::fs::read_dir("/etc/suricata/rules/")
                        .map(|mut d| {
                            d.any(|e| {
                                e.map(|e| {
                                    e.path().extension().and_then(|x| x.to_str()) == Some("rules")
                                })
                                .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false);
                suri.push(if rules_present {
                    Check::ok("Suricata ET rules present")
                } else {
                    Check::warn(
                        "Suricata ET rules not found",
                        if is_macos {
                            "sudo suricata-update && sudo launchctl kickstart -k system/com.suricata"
                        } else {
                            "sudo suricata-update && sudo systemctl restart suricata"
                        },
                    )
                });

                run_section(suri, &mut total_issues);
            }

            // ── osquery ────────────────────────────────────
            if osquery_enabled {
                println!("  osquery");
                let mut osq = Vec::new();

                let osq_binary = std::path::Path::new("/usr/bin/osqueryd").exists()
                    || std::path::Path::new("/usr/local/bin/osqueryd").exists();
                osq.push(if osq_binary {
                    Check::ok("osqueryd binary found")
                } else {
                    Check::fail(
                        "osqueryd binary not found (/usr/bin/osqueryd or /usr/local/bin/osqueryd)",
                        "sudo apt-get install osquery  # see modules/osquery-integration/docs/README.md",
                    )
                });

                let osq_active = if is_macos {
                    std::process::Command::new("launchctl")
                        .args(["list", "com.facebook.osqueryd"])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                } else {
                    systemd::is_service_active("osqueryd")
                };
                let osq_start_hint = if is_macos {
                    "sudo launchctl load /Library/LaunchDaemons/com.facebook.osqueryd.plist"
                } else {
                    "sudo systemctl start osqueryd"
                };
                osq.push(if osq_active {
                    Check::ok("osqueryd service is running")
                } else {
                    Check::warn("osqueryd service is not running", osq_start_hint)
                });

                let results_log = collector_str(
                    "osquery_log",
                    "path",
                    "/var/log/osquery/osqueryd.results.log",
                );
                let results_ok = std::path::Path::new(&results_log).exists();
                osq.push(if results_ok {
                    Check::ok(format!("osquery results log exists ({})", results_log))
                } else {
                    Check::warn(
                        format!("osquery results log not found yet ({})", results_log),
                        "ensure log_result_events=true in /etc/osquery/osquery.conf, then wait 60s for first query",
                    )
                });

                let osq_conf =
                    std::fs::read_to_string("/etc/osquery/osquery.conf").unwrap_or_default();
                let has_schedule = osq_conf.contains("\"schedule\"");
                osq.push(if has_schedule {
                    Check::ok("osquery config contains scheduled queries")
                } else {
                    Check::warn(
                        "osquery config does not contain scheduled queries",
                        "copy the recommended queries from modules/osquery-integration/config/sensor.example.toml into /etc/osquery/osquery.conf",
                    )
                });

                run_section(osq, &mut total_issues);
            }

            // ── nginx-error-monitor ────────────────────────
            if nginx_error_enabled {
                println!("  nginx-error-monitor");
                let mut nginx_err = Vec::new();

                // nginx binary
                let nginx_bin = std::path::Path::new("/usr/sbin/nginx").exists()
                    || std::path::Path::new("/usr/bin/nginx").exists()
                    || std::path::Path::new("/usr/local/sbin/nginx").exists();
                nginx_err.push(if nginx_bin {
                    Check::ok("nginx binary found")
                } else {
                    Check::fail(
                        "nginx binary not found",
                        "sudo apt-get install nginx",
                    )
                });

                // error log path
                let err_log = collector_str(
                    "nginx_error",
                    "path",
                    "/var/log/nginx/error.log",
                );
                let log_exists = std::path::Path::new(&err_log).exists();
                nginx_err.push(if log_exists {
                    Check::ok(format!("nginx error log exists ({})", err_log))
                } else {
                    Check::fail(
                        format!("nginx error log not found ({})", err_log),
                        "sudo systemctl start nginx  # log is created on first request or error",
                    )
                });

                // readability — can the current user read it?
                if log_exists {
                    let readable = std::fs::File::open(&err_log).is_ok();
                    nginx_err.push(if readable {
                        Check::ok(format!("nginx error log is readable ({})", err_log))
                    } else {
                        Check::warn(
                            format!("nginx error log is not readable by innerwarden user ({})", err_log),
                            "sudo usermod -aG adm innerwarden  # or: sudo chmod 640 /var/log/nginx/error.log",
                        )
                    });
                }

                // web_scan detector enabled?
                let web_scan_on = detector_enabled("web_scan");
                nginx_err.push(if web_scan_on {
                    Check::ok("web_scan detector is enabled")
                } else {
                    Check::warn(
                        "web_scan detector is disabled — http.error events are collected but not triaged",
                        "Add to sensor config:\n\n  [detectors.web_scan]\n  enabled = true\n  threshold = 15\n  window_seconds = 60",
                    )
                });

                run_section(nginx_err, &mut total_issues);
            }
        }
    }

    // ── Summary ───────────────────────────────────────────
    println!();
    println!("{}", "─".repeat(48));
    if total_issues == 0 {
        println!("All checks passed — system looks healthy.");
    } else {
        println!("{total_issues} issue(s) found — review hints above.");
        std::process::exit(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_opts(cli: &Cli, params: HashMap<String, String>, yes: bool) -> ActivationOptions {
    ActivationOptions {
        sensor_config: cli.sensor_config.clone(),
        agent_config: cli.agent_config.clone(),
        dry_run: cli.dry_run,
        params,
        yes,
    }
}

fn parse_params(raw: &[String]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for item in raw {
        let (k, v) = item.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("invalid param '{}' — expected KEY=VALUE format", item)
        })?;
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
}

fn unknown_cap_error(id: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "unknown capability '{}' — run 'innerwarden list' to see available capabilities",
        id
    )
}

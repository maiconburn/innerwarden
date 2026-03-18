use crate::incident::Incident;
use crate::signal::Signal;

#[derive(Debug, Default)]
pub struct PolicyDecision {
    pub ignore: bool,
    pub create_incident: bool,
    pub incident: Option<Incident>,
}

/// Policy takes weak signals and decides whether to emit incidents.
///
/// Responsibilities (intended):
/// - ignore/allowlist
/// - elevate severity
/// - dedupe
/// - group signals into incidents
pub fn apply_policy(_signals: &[Signal]) -> Vec<PolicyDecision> {
    Vec::new()
}

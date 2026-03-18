use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entities::EntityRef;
use crate::event::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub ts: DateTime<Utc>,
    pub host: String,
    pub incident_id: String,
    pub severity: Severity,
    pub title: String,
    pub summary: String,
    pub evidence: serde_json::Value,
    pub recommended_checks: Vec<String>,
    pub tags: Vec<String>,
    pub entities: Vec<EntityRef>,
}

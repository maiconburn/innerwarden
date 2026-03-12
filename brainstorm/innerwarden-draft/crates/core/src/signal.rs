use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entities::EntityRef;
use crate::event::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub ts: DateTime<Utc>,
    pub host: String,
    pub detector: String,
    pub kind: String,
    pub severity_hint: Severity,
    pub score: f32,
    pub summary: String,
    pub evidence: serde_json::Value,
    pub tags: Vec<String>,
    pub entities: Vec<EntityRef>,
}

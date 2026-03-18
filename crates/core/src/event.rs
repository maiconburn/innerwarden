use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entities::EntityRef;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Debug,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: DateTime<Utc>,
    pub host: String,
    pub source: String,
    pub kind: String,
    pub severity: Severity,
    pub summary: String,
    pub details: serde_json::Value,
    pub tags: Vec<String>,
    pub entities: Vec<EntityRef>,
}

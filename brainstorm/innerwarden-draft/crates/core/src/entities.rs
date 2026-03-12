use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EntityType {
    Ip,
    User,
    Container,
    Path,
    Service,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EntityRef {
    pub r#type: EntityType,
    pub value: String,
}

impl EntityRef {
    pub fn ip(v: impl Into<String>) -> Self {
        Self { r#type: EntityType::Ip, value: v.into() }
    }
    pub fn user(v: impl Into<String>) -> Self {
        Self { r#type: EntityType::User, value: v.into() }
    }
    pub fn container(v: impl Into<String>) -> Self {
        Self { r#type: EntityType::Container, value: v.into() }
    }
    pub fn path(v: impl Into<String>) -> Self {
        Self { r#type: EntityType::Path, value: v.into() }
    }
    pub fn service(v: impl Into<String>) -> Self {
        Self { r#type: EntityType::Service, value: v.into() }
    }
}

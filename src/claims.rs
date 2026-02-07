use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub domain_roles: Vec<String>,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(default)]
    pub iat: Option<u64>,
}

impl Claims {
    /// Returns true if the subject matches the expected value.
    pub fn is_subject(&self, expected_sub: &str) -> bool {
        self.sub == expected_sub
    }

    /// Returns true if any of the allowed roles is present in domain_roles.
    pub fn allowed_domain_roles(&self, allowed_roles: &[&str]) -> bool {
        allowed_roles
            .iter()
            .any(|role| self.domain_roles.contains(&role.to_string()))
    }
}

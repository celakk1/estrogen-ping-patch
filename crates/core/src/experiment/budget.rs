use crate::AppResult;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resources {
    pub probeAttempts: u64,
    pub providerRequests: u64,
    pub downloadBytes: u64,
    pub uploadBytes: u64,
}

impl Resources {
    fn validate(self) -> AppResult<()> {
        if self.probeAttempts > 1_000_000
            || self.providerRequests > 1_000_000
            || self.downloadBytes > 10 * 1024u64.pow(4)
            || self.uploadBytes > 10 * 1024u64.pow(4)
        {
            return Err("Experiment traffic limits exceed one million probe/request attempts or 10 TiB per payload direction".into());
        }
        Ok(())
    }

    fn add(self, other: Self) -> AppResult<Self> {
        Ok(Self {
            probeAttempts: self
                .probeAttempts
                .checked_add(other.probeAttempts)
                .ok_or("Probe allowance overflow")?,
            providerRequests: self
                .providerRequests
                .checked_add(other.providerRequests)
                .ok_or("Provider request allowance overflow")?,
            downloadBytes: self
                .downloadBytes
                .checked_add(other.downloadBytes)
                .ok_or("Download allowance overflow")?,
            uploadBytes: self
                .uploadBytes
                .checked_add(other.uploadBytes)
                .ok_or("Upload allowance overflow")?,
        })
    }

    fn times(self, count: u64) -> AppResult<Self> {
        Ok(Self {
            probeAttempts: self
                .probeAttempts
                .checked_mul(count)
                .ok_or("Probe reservation overflow")?,
            providerRequests: self
                .providerRequests
                .checked_mul(count)
                .ok_or("Provider request reservation overflow")?,
            downloadBytes: self
                .downloadBytes
                .checked_mul(count)
                .ok_or("Download reservation overflow")?,
            uploadBytes: self
                .uploadBytes
                .checked_mul(count)
                .ok_or("Upload reservation overflow")?,
        })
    }

    fn within(self, limit: Self) -> bool {
        self.probeAttempts <= limit.probeAttempts
            && self.providerRequests <= limit.providerRequests
            && self.downloadBytes <= limit.downloadBytes
            && self.uploadBytes <= limit.uploadBytes
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Provider {
    pub id: String,
    pub perCollection: Resources,
    pub limits: Resources,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrafficBudget {
    pub schemaVersion: u32,
    pub limits: Resources,
    pub providers: Vec<Provider>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderUsage {
    pub id: String,
    pub reserved: Resources,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub reservedBlocks: u32,
    pub reservedCollections: u32,
    pub totals: Resources,
    pub providers: Vec<ProviderUsage>,
}

impl TrafficBudget {
    pub fn bind(&self, expected: &BTreeMap<String, Resources>) -> AppResult<()> {
        self.validate()?;
        if expected.len() != self.providers.len()
            || self.providers.iter().any(|provider| {
                expected
                    .get(&provider.id)
                    .is_none_or(|cost| !cost.within(provider.perCollection))
            })
        {
            return Err("Traffic allowances must cover every trusted collector provider and its maximum collection cost".into());
        }
        Ok(())
    }

    pub fn validate(&self) -> AppResult<()> {
        if self.schemaVersion != 1 || !(1..=16).contains(&self.providers.len()) {
            return Err(
                "Traffic budgets require schema one and one to sixteen fixed provider identities"
                    .into(),
            );
        }
        self.limits.validate()?;
        let mut ids = BTreeSet::new();
        let mut total = Resources::default();
        for provider in &self.providers {
            if provider.id.is_empty()
                || provider.id.len() > 100
                || provider.id.chars().any(char::is_control)
                || !ids.insert(&provider.id)
                || provider.perCollection == Resources::default()
            {
                return Err("Every traffic provider needs a distinct bounded identity and nonzero collection allowance".into());
            }
            provider.perCollection.validate()?;
            provider.limits.validate()?;
            total = total.add(provider.perCollection)?;
        }
        total.validate()
    }

    pub fn usage(&self, blocks: u32) -> AppResult<Usage> {
        self.validate()?;
        if blocks > 32 {
            return Err("Traffic reservations exceed the experiment block limit".into());
        }
        let collections = blocks
            .checked_mul(3)
            .ok_or("Collection reservation overflow")?;
        let mut total = Resources::default();
        let mut providers = Vec::with_capacity(self.providers.len());
        for provider in &self.providers {
            let reserved = provider.perCollection.times(u64::from(collections))?;
            total = total.add(reserved)?;
            providers.push(ProviderUsage {
                id: provider.id.clone(),
                reserved,
            });
        }
        Ok(Usage {
            reservedBlocks: blocks,
            reservedCollections: collections,
            totals: total,
            providers,
        })
    }

    pub fn allows(&self, blocks: u32) -> AppResult<bool> {
        let usage = self.usage(blocks)?;
        Ok(usage.totals.within(self.limits)
            && usage
                .providers
                .iter()
                .zip(&self.providers)
                .all(|(used, provider)| used.reserved.within(provider.limits)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflowUnknownProvidersAndOperationallyUnboundedAllowancesAreRejected() {
        assert!(
            Resources {
                downloadBytes: u64::MAX,
                ..Default::default()
            }
            .times(3)
            .is_err()
        );
        let provider = Provider {
            id: "test".into(),
            perCollection: Resources {
                probeAttempts: 1,
                ..Default::default()
            },
            limits: Resources::default(),
        };
        let mut budget = TrafficBudget {
            schemaVersion: 1,
            limits: Resources::default(),
            providers: vec![provider.clone()],
        };
        assert!(budget.validate().is_ok());
        assert!(!budget.allows(1).unwrap());
        budget.providers.push(provider);
        assert!(budget.validate().is_err());
        budget.providers.pop();
        budget.limits.downloadBytes = u64::MAX;
        assert!(budget.validate().is_err());
    }
}

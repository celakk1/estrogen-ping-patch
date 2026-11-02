use super::*;
use epp_core::experiment::{Plan, budget::Resources};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preview {
    pub schemaVersion: u32,
    pub mtu: MtuPreview,
    pub plan: Plan,
    pub maximumTrialDurationMs: u64,
    pub scopeSha256: String,
}

struct Scope {
    preview: Preview,
    deadline: Instant,
}

pub struct SessionConsent {
    consent: MtuConsent,
    pending: Option<Scope>,
}

pub struct ApprovedSession {
    approval: crate::authorization::Approval,
    template: MtuCheckpoint,
    planSha256: String,
    plan: Plan,
    maximumTrialDurationMs: u64,
    approvedAtUnixMs: u64,
    highWaterUnixMs: u64,
    deadline: Instant,
    stopped: bool,
    checkpoints: BTreeSet<Uuid>,
    grants: Vec<Uuid>,
}

fn hash(value: &impl Serialize) -> ServiceResult<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

impl SessionConsent {
    pub fn new(ownerSid: &str) -> ServiceResult<Self> {
        Ok(Self {
            consent: MtuConsent::new(ownerSid)?,
            pending: None,
        })
    }

    pub fn preview(
        &mut self,
        template: MtuCheckpoint,
        plan: Plan,
        trustedCosts: &BTreeMap<String, Resources>,
        actorSid: &str,
        nowUnixMs: u64,
    ) -> ServiceResult<Preview> {
        self.consent.checkActor(actorSid)?;
        self.consent.expire(nowUnixMs);
        plan.validate()?;
        template.validate()?;
        let budget = plan
            .trafficBudget
            .as_ref()
            .ok_or("Session consent requires explicit traffic limits")?;
        budget.bind(trustedCosts)?;
        let maximumTrialDurationMs = template.leaseExpiresAtUnixMs - template.createdAtUnixMs;
        let native = template
            .nativeOriginal
            .as_ref()
            .ok_or("Session consent requires a native original")?;
        let mut candidate = native.settings.clone();
        candidate.nlMtu = template.proposedMtu;
        if template.schemaVersion != 4
            || !(5000..=300_000).contains(&maximumTrialDurationMs)
            || !(1280..template.originalMtu).contains(&template.proposedMtu)
            || plan.createdAtUnixMs > nowUnixMs
            || nowUnixMs >= plan.expiresAtUnixMs
            || template.leaseExpiresAtUnixMs > plan.expiresAtUnixMs
            || hash(&native.settings)? != plan.comparison.originalConfigurationSha256
            || hash(&candidate)? != plan.comparison.candidateConfigurationSha256
            || !budget.allows(plan.blockCount as u32)?
        {
            return Err("Session consent requires a current exact MTU reduction, matching configurations, and traffic limits covering every planned bracket".into());
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(plan.expiresAtUnixMs - nowUnixMs))
            .ok_or("Session monotonic deadline overflow")?;
        let mtu = self.consent.preview(template, actorSid, nowUnixMs)?;
        let scopeSha256 = hash(&(&mtu, &plan, maximumTrialDurationMs))?;
        let preview = Preview {
            schemaVersion: 1,
            mtu,
            plan,
            maximumTrialDurationMs,
            scopeSha256,
        };
        self.pending = Some(Scope {
            preview: preview.clone(),
            deadline,
        });
        Ok(preview)
    }

    pub fn approve(
        &mut self,
        previewId: Uuid,
        scopeSha256: &str,
        actorSid: &str,
        nowUnixMs: u64,
    ) -> ServiceResult<ApprovedSession> {
        self.consent.checkActor(actorSid)?;
        self.consent
            .currentPreview(nowUnixMs)
            .ok_or("Session preview is missing, expired, cancelled, or already used")?;
        let scope = self.pending.as_ref().ok_or("Session scope missing")?;
        if scope.preview.mtu.previewId != previewId || scope.preview.scopeSha256 != scopeSha256 {
            return Err("Session approval does not match the complete reviewed plan".into());
        }
        let approval = self.consent.takeApproval(
            previewId,
            &scope.preview.mtu.checkpointSha256,
            actorSid,
            nowUnixMs,
        )?;
        let scope = self.pending.take().ok_or("Session scope was consumed")?;
        Ok(ApprovedSession {
            approval: crate::authorization::Approval {
                actorSid: actorSid.into(),
                approvedAtUnixMs: nowUnixMs,
                scopeJson: serde_json::to_string(&(
                    &scope.preview.mtu,
                    &scope.preview.plan,
                    scope.preview.maximumTrialDurationMs,
                ))?,
                scopeSha256: scope.preview.scopeSha256,
            },
            template: approval.pending.document,
            planSha256: hash(&scope.preview.plan)?,
            plan: scope.preview.plan,
            maximumTrialDurationMs: scope.preview.maximumTrialDurationMs,
            approvedAtUnixMs: nowUnixMs,
            highWaterUnixMs: nowUnixMs,
            deadline: scope.deadline,
            stopped: false,
            checkpoints: BTreeSet::new(),
            grants: Vec::new(),
        })
    }

    pub fn cancel(&mut self, previewId: Uuid, actorSid: &str) -> ServiceResult<()> {
        self.consent.cancel(previewId, actorSid)?;
        self.pending = None;
        Ok(())
    }
}

impl ApprovedSession {
    fn checkActor(&self, actorSid: &str) -> ServiceResult<()> {
        validateSid(actorSid)?;
        if actorSid != self.template.authorizedUserSid {
            return Err("Approved session belongs to a different Windows user".into());
        }
        Ok(())
    }

    fn checkTime(&mut self, nowUnixMs: u64) -> ServiceResult<()> {
        if self.stopped
            || nowUnixMs < self.highWaterUnixMs
            || nowUnixMs >= self.plan.expiresAtUnixMs
            || Instant::now() >= self.deadline
        {
            self.stopped = true;
            return Err("Session approval is expired, cancelled, or invalidated".into());
        }
        self.highWaterUnixMs = nowUnixMs;
        Ok(())
    }

    pub fn issue(
        &mut self,
        document: &MtuCheckpoint,
        plan: &Plan,
        actorSid: &str,
        store: &mut AuthorizationStore,
        nowUnixMs: u64,
    ) -> ServiceResult<MtuGrant> {
        self.checkActor(actorSid)?;
        self.checkTime(nowUnixMs)?;
        document.validate()?;
        let original = self
            .template
            .nativeOriginal
            .as_ref()
            .ok_or("Original missing")?;
        let fresh = document
            .nativeOriginal
            .as_ref()
            .ok_or("Fresh native original missing")?;
        fresh.validateMtuObservation(original)?;
        if hash(plan)? != self.planSha256
            || document.schemaVersion != 4
            || document.context != self.template.context
            || document.addressFamily != self.template.addressFamily
            || document.authorizedUserSid != self.template.authorizedUserSid
            || document.originalMtu != self.template.originalMtu
            || document.proposedMtu != self.template.proposedMtu
            || document.policyOriginal != self.template.policyOriginal
            || fresh.settings != original.settings
            || document.createdAtUnixMs < self.approvedAtUnixMs
            || document.createdAtUnixMs > nowUnixMs
            || document.leaseExpiresAtUnixMs <= nowUnixMs
            || document.leaseExpiresAtUnixMs > self.plan.expiresAtUnixMs
            || document.leaseExpiresAtUnixMs - document.createdAtUnixMs
                > self.maximumTrialDurationMs
            || document.leaseExpiresAtUnixMs - document.createdAtUnixMs < 5000
            || document.id == self.template.id
            || self.checkpoints.contains(&document.id)
            || self.checkpoints.len() >= self.plan.blockCount
        {
            return Err("Trial exceeds the approved session's exact plan, original, identity, candidate, lease, or checkpoint allowance".into());
        }
        // consume the allowance before storage; an ambiguous commit ends delegation.
        self.checkpoints.insert(document.id);
        let trialDeadline = Instant::now()
            .checked_add(Duration::from_millis(
                document.leaseExpiresAtUnixMs - nowUnixMs,
            ))
            .ok_or("Trial monotonic deadline overflow")?;
        match store.issueSession(document, actorSid, &self.approval, nowUnixMs) {
            Ok(grant) => {
                self.grants.push(grant.id);
                if Instant::now() >= self.deadline || Instant::now() >= trialDeadline {
                    self.stopped = true;
                    store.revoke(grant.id, actorSid, nowUnixMs).map_err(|error|
                        format!("Session expired during grant storage and revocation failed: {error}"))?;
                    return Err(
                        "Session or trial expired while permission storage was committing".into(),
                    );
                }
                Ok(grant)
            }
            Err(error) => {
                self.stopped = true;
                Err(error)
            }
        }
    }

    pub fn cancel(
        &mut self,
        actorSid: &str,
        store: &mut AuthorizationStore,
        nowUnixMs: u64,
    ) -> ServiceResult<()> {
        self.checkActor(actorSid)?;
        self.stopped = true;
        let mut failure = None;
        for id in &self.grants {
            if let Err(error) = store.revoke(*id, actorSid, nowUnixMs) {
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests;

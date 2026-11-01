use epp_core::benchmark::{Endpoint, RoutingEvidence, RoutingStatus};
use serde_json::{Value, json};
use std::sync::atomic::AtomicBool;

pub(crate) struct Captured {
    values: Value,
    fingerprint: Option<String>,
}

pub(crate) fn destinations(
    endpoints: &[Endpoint],
) -> Result<Vec<epp_service::routing::Address>, String> {
    endpoints
        .iter()
        .map(|endpoint| {
            endpoint
                .destinationAddress()
                .map(|(ip, scopeId)| epp_service::routing::Address { ip, scopeId })
                .map_err(|error| error.to_string())
        })
        .collect()
}

pub(crate) fn capture(
    destinations: &[epp_service::routing::Address],
    cancelled: &AtomicBool,
) -> Captured {
    let result = (|| -> epp_service::ServiceResult<Captured> {
        let captures = epp_service::routing::capture(destinations, cancelled)?;
        let fingerprint = epp_service::routing::fingerprint(&captures)?;
        Ok(Captured {
            values: serde_json::to_value(captures)?,
            fingerprint,
        })
    })();
    match result {
        Ok(value) => value,
        Err(error) => Captured {
            values: json!({"status":"unavailable","error":error.to_string().chars().take(512).collect::<String>()}),
            fingerprint: None,
        },
    }
}

pub(crate) fn evidence(before: Captured, after: Captured) -> RoutingEvidence {
    let status = match (&before.fingerprint, &after.fingerprint) {
        (Some(first), Some(second)) if first == second => RoutingStatus::Unchanged,
        (Some(_), Some(_)) => RoutingStatus::Changed,
        _ => RoutingStatus::Unavailable,
    };
    RoutingEvidence {
        schemaVersion: 1,
        status,
        beforeFingerprint: before.fingerprint,
        afterFingerprint: after.fingerprint,
        before: before.values,
        after: after.values,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellationPreservesUnavailableEvidenceInsteadOfInventingStableRoutes() {
        let destination = epp_service::routing::Address {
            ip: "127.0.0.1".parse().unwrap(),
            scopeId: 0,
        };
        let cancelled = AtomicBool::new(true);
        let before = capture(std::slice::from_ref(&destination), &cancelled);
        let after = capture(&[destination], &cancelled);
        let evidence = evidence(before, after);
        assert!(matches!(evidence.status, RoutingStatus::Unavailable));
        assert!(evidence.beforeFingerprint.is_none() && evidence.afterFingerprint.is_none());
        assert_eq!(evidence.before["status"], "unavailable");
        assert!(
            evidence.after["error"]
                .as_str()
                .unwrap()
                .contains("cancelled")
        );
    }
}

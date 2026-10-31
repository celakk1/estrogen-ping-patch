use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub attempted: usize,
    pub successful: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connectionFailurePercent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub echoTimeoutPercent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnsFailurePercent: Option<f64>,
    pub medianMs: Option<f64>,
    pub p95Ms: Option<f64>,
    pub p99Ms: Option<f64>,
    pub iqrMs: Option<f64>,
    pub successiveVariationMs: Option<f64>,
}

fn quantile(sorted: &[f64], probability: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let index = (sorted.len() - 1) as f64 * probability;
    let lower = index.floor() as usize;
    let upper = index.ceil() as usize;
    Some(sorted[lower] + (sorted[upper] - sorted[lower]) * index.fract())
}

pub fn summarize(samples: &[Option<f64>]) -> Summary {
    let mut sorted: Vec<f64> = samples
        .iter()
        .flatten()
        .copied()
        .filter(|value| value.is_finite() && *value >= 0.0)
        .collect();
    sorted.sort_by(f64::total_cmp);
    let variations: Vec<f64> = samples
        .windows(2)
        .filter_map(|pair| match (pair[0], pair[1]) {
            (Some(first), Some(second))
                if first.is_finite() && second.is_finite() && first >= 0.0 && second >= 0.0 =>
            {
                Some((second - first).abs())
            }
            _ => None,
        })
        .collect();
    Summary {
        attempted: samples.len(),
        successful: sorted.len(),
        connectionFailurePercent: Some(if samples.is_empty() {
            0.0
        } else {
            (samples.len() - sorted.len()) as f64 * 100.0 / samples.len() as f64
        }),
        echoTimeoutPercent: None,
        dnsFailurePercent: None,
        medianMs: quantile(&sorted, 0.5),
        p95Ms: quantile(&sorted, 0.95),
        p99Ms: quantile(&sorted, 0.99),
        iqrMs: quantile(&sorted, 0.75)
            .zip(quantile(&sorted, 0.25))
            .map(|(upper, lower)| upper - lower),
        successiveVariationMs: if variations.is_empty() {
            None
        } else {
            Some(variations.iter().sum::<f64>() / variations.len() as f64)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantilesAndFailuresAreProtocolSpecific() {
        let summary = summarize(&[Some(1.0), Some(2.0), None, Some(3.0), Some(4.0)]);
        assert_eq!(summary.medianMs, Some(2.5));
        assert_eq!(summary.connectionFailurePercent, Some(20.0));
        assert_eq!(summary.successiveVariationMs, Some(1.0));
        assert_eq!(summary.iqrMs, Some(1.5));
    }

    #[test]
    fn noFabricatedValuesWhenEveryConnectionFails() {
        let summary = summarize(&[None, None, None]);
        assert_eq!(summary.medianMs, None);
        assert_eq!(summary.connectionFailurePercent, Some(100.0));
        assert_eq!(summary.successiveVariationMs, None);
    }

    #[test]
    fn invalidNumbersCannotBecomeMeasurements() {
        let summary = summarize(&[Some(f64::NAN), Some(-2.0), Some(4.0)]);
        assert_eq!(summary.successful, 1);
        assert_eq!(summary.p99Ms, Some(4.0));
    }

    #[test]
    fn serializedTimingsRoundTripWithoutChangingFloatingPointBits() {
        let value = 0.42969999999999997_f64;
        let json = serde_json::to_string(&value).unwrap();
        let saved: f64 = serde_json::from_str(&json).unwrap();
        assert_eq!(
            saved.to_bits(),
            value.to_bits(),
            "Changed persisted timing: {json}"
        );
    }
}

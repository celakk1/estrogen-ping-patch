use super::*;

fn reference(differences: &[Vec<f64>], seed: [u8; 32]) -> Vec<Interval> {
    let count = differences[0].len();
    let mut indices = Indices::new(seed);
    let mut distributions = vec![Vec::with_capacity(RESAMPLES); differences.len()];
    let mut sums = vec![0.0; differences.len()];
    for _ in 0..RESAMPLES {
        sums.fill(0.0);
        for _ in 0..count {
            let index = indices.next(count);
            for (sum, values) in sums.iter_mut().zip(differences) {
                *sum += values[index];
            }
        }
        for (distribution, sum) in distributions.iter_mut().zip(&sums) {
            distribution.push(sum / count as f64);
        }
    }
    let alpha = 0.05 / differences.len() as f64;
    distributions
        .into_iter()
        .map(|mut distribution| {
            distribution.sort_by(f64::total_cmp);
            Interval {
                lower: quantile(&distribution, alpha / 2.0),
                upper: quantile(&distribution, 1.0 - alpha / 2.0),
                nominalConfidence: 1.0 - alpha,
                degenerate: distribution.first() == distribution.last(),
            }
        })
        .collect()
}

fn differences(series: usize, count: usize) -> Vec<Vec<f64>> {
    (0..series)
        .map(|series| {
            (0..count)
                .map(|block| ((series + 11) * block % 7) as f64 - 3.0)
                .collect()
        })
        .collect()
}

#[test]
fn batchedIntervalsAreBitIdenticalToTheOriginalPairedAlgorithm() {
    for series in [1, BATCH_SERIES - 1, BATCH_SERIES, BATCH_SERIES + 1, 192] {
        let differences = differences(series, 12);
        let expected = reference(&differences, [29; 32]);
        let actual = intervals(&differences, [29; 32], &mut || Ok(())).unwrap();
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(&expected) {
            assert_eq!(actual.lower.to_bits(), expected.lower.to_bits(), "{series}");
            assert_eq!(actual.upper.to_bits(), expected.upper.to_bits(), "{series}");
            assert_eq!(
                actual.nominalConfidence.to_bits(),
                expected.nominalConfidence.to_bits(),
                "{series}"
            );
            assert_eq!(actual.degenerate, expected.degenerate);
        }
    }
}

#[test]
fn cancellationCanStopDrawPreparationAndEachDistributionBatch() {
    let differences = differences(BATCH_SERIES + 1, 12);
    let mut completeChecks = 0;
    intervals(&differences, [7; 32], &mut || {
        completeChecks += 1;
        Ok(())
    })
    .unwrap();
    for stopAt in [1, 2, 100, 258, 259, 400, completeChecks - 1, completeChecks] {
        let mut checks = 0;
        let result = intervals(&differences, [7; 32], &mut || {
            checks += 1;
            if checks == stopAt {
                Err("fixture analysis cancelled".into())
            } else {
                Ok(())
            }
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("fixture analysis cancelled")
        );
        assert_eq!(checks, stopAt);
    }
}

#[test]
fn invalidSeriesFailBeforeResampleAllocation() {
    for differences in [
        Vec::new(),
        vec![Vec::new()],
        differences(super::super::MAX_METRICS * 3 + 1, 12),
        differences(1, super::super::MAX_BLOCKS + 1),
        vec![vec![0.0], vec![0.0, 1.0]],
        vec![vec![f64::NAN]],
    ] {
        let mut checks = 0;
        assert!(
            intervals(&differences, [7; 32], &mut || {
                checks += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(checks, 1);
    }
}

use crate::AppResult;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub(super) const RESAMPLES: usize = 16384;
const BATCH_SERIES: usize = 48;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Interval {
    pub lower: f64,
    pub upper: f64,
    pub nominalConfidence: f64,
    pub degenerate: bool,
}

struct Indices {
    seed: [u8; 32],
    counter: u64,
    words: [u64; 4],
    nextWord: usize,
}

impl Indices {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            words: [0; 4],
            nextWord: 4,
        }
    }

    fn next(&mut self, count: usize) -> usize {
        loop {
            if self.nextWord == 4 {
                let mut hash = Sha256::new();
                hash.update(self.seed);
                hash.update(self.counter.to_le_bytes());
                let bytes = hash.finalize();
                for (word, chunk) in self.words.iter_mut().zip(bytes.as_chunks::<8>().0) {
                    *word = u64::from_le_bytes(*chunk);
                }
                self.counter += 1;
                self.nextWord = 0;
            }
            let value = self.words[self.nextWord];
            self.nextWord += 1;
            let bound = count as u64;
            let zone = u64::MAX - u64::MAX % bound;
            if value < zone {
                return (value % bound) as usize;
            }
        }
    }
}

fn quantile(sorted: &[f64], probability: f64) -> f64 {
    let position = (sorted.len() - 1) as f64 * probability;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    sorted[lower] + (sorted[upper] - sorted[lower]) * position.fract()
}

pub(super) fn intervals(
    differences: &[Vec<f64>],
    seed: [u8; 32],
    check: &mut impl FnMut() -> AppResult<()>,
) -> AppResult<Vec<Interval>> {
    check()?;
    if differences.is_empty() || differences.len() > super::MAX_METRICS * 3 {
        return Err("Bootstrap series exceed the comparison allowance".into());
    }
    let count = differences[0].len();
    if !(1..=super::MAX_BLOCKS).contains(&count)
        || differences
            .iter()
            .any(|values| values.len() != count || values.iter().any(|value| !value.is_finite()))
    {
        return Err("Bootstrap series require matching bounded finite block values".into());
    }
    check()?;
    let mut indices = Indices::new(seed);
    // every batch replays these exact draws to preserve paired metrics.
    let mut draws = Vec::with_capacity(RESAMPLES * count);
    for resample in 0..RESAMPLES {
        if resample % 64 == 0 {
            check()?;
        }
        for _ in 0..count {
            draws.push(u8::try_from(indices.next(count))?);
        }
    }
    let alpha = 0.05 / differences.len() as f64;
    let mut result = Vec::with_capacity(differences.len());
    for batch in differences.chunks(BATCH_SERIES) {
        check()?;
        let mut distributions: Vec<_> = (0..batch.len())
            .map(|_| Vec::with_capacity(RESAMPLES))
            .collect();
        let mut sums = vec![0.0; batch.len()];
        for (resample, draw) in draws.chunks_exact(count).enumerate() {
            if resample % 64 == 0 {
                check()?;
            }
            sums.fill(0.0);
            for index in draw {
                for (sum, values) in sums.iter_mut().zip(batch) {
                    *sum += values[usize::from(*index)];
                }
            }
            for (distribution, sum) in distributions.iter_mut().zip(&sums) {
                distribution.push(sum / count as f64);
            }
        }
        for mut distribution in distributions {
            check()?;
            distribution.sort_by(f64::total_cmp);
            result.push(Interval {
                lower: quantile(&distribution, alpha / 2.0),
                upper: quantile(&distribution, 1.0 - alpha / 2.0),
                nominalConfidence: 1.0 - alpha,
                degenerate: distribution.first() == distribution.last(),
            });
        }
    }
    check()?;
    Ok(result)
}

#[cfg(test)]
mod tests;

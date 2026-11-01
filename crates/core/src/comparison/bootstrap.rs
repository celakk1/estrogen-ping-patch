use serde::Serialize;
use sha2::{Digest, Sha256};

pub(super) const RESAMPLES: usize = 16384;

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

pub(super) fn intervals(differences: &[Vec<f64>], seed: [u8; 32]) -> Vec<Interval> {
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

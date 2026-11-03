use super::*;

pub(super) const FRAME_BYTES: usize = 65536;
pub(super) const STREAM_BYTES: usize = 4 * 1024 * 1024;
const MAX_FRAMES: u32 = 4096;
const FRAME_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Counters {
    pub downloadBytesRead: u64,
    pub uploadBodyBytesProvided: u64,
    pub activeRequests: u64,
}

impl Counters {
    fn read(progress: &TransferProgress) -> Self {
        Self {
            downloadBytesRead: progress.downloadBytesRead.load(Ordering::SeqCst),
            uploadBodyBytesProvided: progress.uploadBodyBytesProvided.load(Ordering::SeqCst),
            activeRequests: progress.activeRequests.load(Ordering::SeqCst),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub elapsedMicros: u64,
    pub counters: Counters,
}

// delivery is provisional and delayed; these observations do not qualify latency probes.
#[derive(Clone, Copy, Debug)]
pub struct ProgressUpdate {
    pub observation: Observation,
    pub receivedAt: Instant,
}

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "data",
    rename_all = "camelCase",
    deny_unknown_fields
)]
enum Event {
    Progress(Observation),
    Result(Box<Response>),
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Frame {
    version: u32,
    sequence: u32,
    event: Event,
}

pub(super) struct Encoder<W: Write> {
    output: W,
    sequence: u32,
    bytes: usize,
    counters: Counters,
}

impl<W: Write> Encoder<W> {
    pub(super) fn new(output: W) -> Self {
        Self {
            output,
            sequence: 0,
            bytes: 0,
            counters: Counters::default(),
        }
    }

    fn send(&mut self, event: Event) -> ServiceResult<()> {
        let bytes = serde_json::to_vec(&Frame {
            version: FRAME_VERSION,
            sequence: self.sequence,
            event,
        })?;
        if self.sequence >= MAX_FRAMES
            || bytes.len() >= FRAME_BYTES
            || self.bytes + bytes.len() + 1 > STREAM_BYTES
        {
            return Err("Benchmark worker frames exceeded their fixed allowance".into());
        }
        self.output.write_all(&bytes)?;
        self.output.write_all(b"\n")?;
        self.output.flush()?;
        self.bytes += bytes.len() + 1;
        self.sequence += 1;
        Ok(())
    }

    pub(super) fn progress(
        &mut self,
        progress: &TransferProgress,
        started: Instant,
    ) -> ServiceResult<()> {
        let counters = Counters::read(progress);
        if counters != self.counters {
            self.send(Event::Progress(Observation {
                elapsedMicros: started.elapsed().as_micros().try_into()?,
                counters,
            }))?;
            self.counters = counters;
        }
        Ok(())
    }

    pub(super) fn finish(&mut self, result: TransferResult) -> ServiceResult<()> {
        self.send(Event::Result(Box::new(Response {
            schemaVersion: SCHEMA_VERSION,
            result,
        })))
    }
}

pub(super) struct Decoder<'a> {
    input: &'a Request,
    partial: Vec<u8>,
    bytes: usize,
    sequence: u32,
    counters: Counters,
    elapsedMicros: u64,
    activeTransitions: u64,
    result: Option<TransferResult>,
}

impl<'a> Decoder<'a> {
    pub(super) fn new(input: &'a Request) -> Self {
        Self {
            input,
            partial: Vec::new(),
            bytes: 0,
            sequence: 0,
            counters: Counters::default(),
            elapsedMicros: 0,
            activeTransitions: 0,
            result: None,
        }
    }

    pub(super) fn consume(
        &mut self,
        bytes: &[u8],
        onProgress: &mut impl FnMut(ProgressUpdate) -> ServiceResult<()>,
    ) -> ServiceResult<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or("Benchmark worker frame size overflowed")?;
        if self.bytes > STREAM_BYTES {
            return Err("Benchmark worker stream exceeded its fixed allowance".into());
        }
        for piece in bytes.split_inclusive(|byte| *byte == b'\n') {
            if self.result.is_some() {
                return Err("Benchmark worker sent data after its terminal result".into());
            }
            if self.partial.len() + piece.len() > FRAME_BYTES {
                return Err("Benchmark worker frame exceeded its fixed allowance".into());
            }
            self.partial.extend_from_slice(piece);
            if self.partial.last() == Some(&b'\n') {
                let mut line = std::mem::take(&mut self.partial);
                line.pop();
                self.frame(&line, onProgress)?;
                line.clear();
                self.partial = line;
            }
        }
        Ok(())
    }

    fn frame(
        &mut self,
        bytes: &[u8],
        onProgress: &mut impl FnMut(ProgressUpdate) -> ServiceResult<()>,
    ) -> ServiceResult<()> {
        if self.sequence >= MAX_FRAMES {
            return Err("Benchmark worker sent too many frames".into());
        }
        let frame: Frame = serde_json::from_slice(bytes).map_err(|error| {
            let diagnostic: String = String::from_utf8_lossy(bytes)
                .chars()
                .take(512)
                .map(|character| {
                    if character.is_control() {
                        ' '
                    } else {
                        character
                    }
                })
                .collect();
            format!(
                "Benchmark worker sent an invalid frame: {error}. Worker diagnostic: {diagnostic}"
            )
        })?;
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        if serde_json::to_value(&frame)? != value
            || frame.version != FRAME_VERSION
            || frame.sequence != self.sequence
        {
            return Err("Benchmark worker frame schema, fields, or sequence changed".into());
        }
        self.sequence += 1;
        match frame.event {
            Event::Progress(observation) => {
                let next = observation.counters;
                self.activeTransitions = self
                    .activeTransitions
                    .checked_add(next.activeRequests.abs_diff(self.counters.activeRequests))
                    .ok_or("Benchmark worker activity count overflowed")?;
                if next == self.counters
                    || next.downloadBytesRead < self.counters.downloadBytesRead
                    || next.uploadBodyBytesProvided < self.counters.uploadBodyBytesProvided
                    || next.downloadBytesRead > self.input.plan.bytes
                    || next.uploadBodyBytesProvided > self.input.plan.bytes
                    || (self.input.plan.direction == Direction::Download
                        && next.uploadBodyBytesProvided != 0)
                    || (self.input.plan.direction == Direction::Upload
                        && next.downloadBytesRead != 0)
                    || next.activeRequests > u64::from(self.input.plan.streams)
                    || self.activeTransitions > 2 * u64::from(self.input.plan.streams)
                    || observation.elapsedMicros < self.elapsedMicros
                    || observation.elapsedMicros > self.input.plan.timeoutMs * 1000 + 1_000_000
                {
                    return Err(
                        "Benchmark worker progress contradicts its fixed transfer allowance".into(),
                    );
                }
                self.counters = next;
                self.elapsedMicros = observation.elapsedMicros;
                onProgress(ProgressUpdate {
                    observation,
                    receivedAt: Instant::now(),
                })?;
            }
            Event::Result(response) => {
                validateResult(self.input, &response)?;
                let counters = Counters {
                    downloadBytesRead: response
                        .result
                        .streams
                        .iter()
                        .map(|stream| stream.downloadBytesRead)
                        .sum(),
                    uploadBodyBytesProvided: response
                        .result
                        .streams
                        .iter()
                        .map(|stream| stream.uploadBodyBytesProvided)
                        .sum(),
                    activeRequests: 0,
                };
                if counters != self.counters {
                    return Err("Benchmark worker result disagrees with its final counters".into());
                }
                self.result = Some(response.result);
            }
        }
        Ok(())
    }

    pub(super) fn finish(self) -> ServiceResult<TransferResult> {
        if !self.partial.is_empty() {
            return Err("Benchmark worker exited within a frame".into());
        }
        self.result
            .ok_or_else(|| "Benchmark worker exited without a terminal result".into())
    }
}

#[cfg(test)]
mod tests;

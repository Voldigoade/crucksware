use std::{
    io::{self, IsTerminal},
    time::{Duration, Instant},
};

use crucksware::{
    error::Side,
    progress::{ProgressEvent, ProgressPhase},
};
use indicatif::{ProgressBar, ProgressDrawTarget};

const REDRAW_INTERVAL: Duration = Duration::from_millis(100);
const SPINNER_INTERVAL: Duration = Duration::from_millis(120);

pub(super) struct ProgressRenderer {
    state: ProgressState,
    bar: Option<ProgressBar>,
    last_message_update: Instant,
}

impl ProgressRenderer {
    pub(super) fn new() -> Option<Self> {
        Self::for_terminal(io::stderr().is_terminal())
    }

    fn for_terminal(stderr_is_terminal: bool) -> Option<Self> {
        stderr_is_terminal.then(|| Self {
            state: ProgressState::default(),
            bar: None,
            last_message_update: Instant::now(),
        })
    }

    pub(super) fn on_event(&mut self, event: ProgressEvent) {
        match event {
            ProgressEvent::PhaseStarted { .. } => {
                self.state.observe(event);
                self.start_phase();
            }
            ProgressEvent::PhaseTotalKnown { .. } => {
                self.state.observe(event);
                self.update_message(true);
            }
            ProgressEvent::PhaseCompleted { .. } => {
                self.update_message(true);
                self.state.observe(event);
                self.finish();
            }
            _ => {
                self.state.observe(event);
                self.update_message(false);
            }
        }
    }

    pub(super) fn finish(&mut self) {
        if let Some(bar) = self.bar.take() {
            bar.finish_and_clear();
        }
    }

    fn start_phase(&mut self) {
        self.finish();
        let bar = ProgressBar::new_spinner();
        bar.set_draw_target(ProgressDrawTarget::stderr_with_hz(10));
        bar.enable_steady_tick(SPINNER_INTERVAL);
        self.bar = Some(bar);
        self.update_message(true);
    }

    fn update_message(&mut self, force: bool) {
        let now = Instant::now();
        if !force && now.duration_since(self.last_message_update) < REDRAW_INTERVAL {
            return;
        }
        if let (Some(bar), Some(message)) = (&self.bar, self.state.message()) {
            bar.set_message(message);
            if force {
                bar.force_draw();
            }
            self.last_message_update = now;
        }
    }
}

#[derive(Default)]
struct ProgressState {
    phase: Option<ProgressPhase>,
    old_entries: u64,
    new_entries: u64,
    completed: u64,
    total: Option<u64>,
    bytes_read: u64,
    changes: u64,
}

impl ProgressState {
    fn observe(&mut self, event: ProgressEvent) {
        match event {
            ProgressEvent::PhaseStarted { phase, total } => {
                self.phase = Some(phase);
                self.completed = 0;
                self.total = total;
            }
            ProgressEvent::PhaseTotalKnown { phase, total } if self.phase == Some(phase) => {
                self.total = Some(total);
            }
            ProgressEvent::EntryDiscovered { side, entries } => match side {
                Side::Old => self.old_entries = entries,
                Side::New => self.new_entries = entries,
            },
            ProgressEvent::BytesRead { total_bytes_read } => self.bytes_read = total_bytes_read,
            ProgressEvent::ChangeDiscovered { .. } => {
                self.changes = self.changes.saturating_add(1);
            }
            ProgressEvent::PhaseProgress {
                phase,
                completed,
                total,
            } if self.phase == Some(phase) => {
                self.completed = completed;
                self.total = Some(total);
            }
            ProgressEvent::PhaseCompleted { phase } if self.phase == Some(phase) => {
                self.phase = None;
            }
            ProgressEvent::PhaseTotalKnown { .. }
            | ProgressEvent::PhaseProgress { .. }
            | ProgressEvent::PhaseCompleted { .. } => {}
        }
    }

    fn message(&self) -> Option<String> {
        let suffix = match self.phase? {
            ProgressPhase::Inventory(side) => {
                let entries = match side {
                    Side::Old => self.old_entries,
                    Side::New => self.new_entries,
                };
                return Some(format!(
                    "Indexing {side}: {} entries",
                    format_count(entries)
                ));
            }
            ProgressPhase::Comparing if self.total.is_none() => "Counting paths".to_owned(),
            ProgressPhase::Comparing => format!(
                "Comparing {} / {} entries",
                format_count(self.completed),
                format_count(self.total?)
            ),
            ProgressPhase::Revalidation(side) => format!(
                "Verifying {side}: {} / {} checks",
                format_count(self.completed),
                format_count(self.total?)
            ),
        };
        Some(format!(
            "{suffix} | {} read | {} found",
            format_bytes(self.bytes_read),
            format_changes(self.changes)
        ))
    }
}

fn format_changes(count: u64) -> String {
    format!(
        "{} {}",
        format_count(count),
        plural(count, "change", "changes")
    )
}

fn plural(count: u64, singular: &'static str, plural: &'static str) -> &'static str {
    if count == 1 { singular } else { plural }
}

fn format_count(count: u64) -> String {
    let digits = count.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.bytes().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(char::from(digit));
    }
    output
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

    let mut unit = 0;
    let mut divisor = 1_u64;
    while unit + 1 < UNITS.len() && bytes / divisor >= 1_024 {
        divisor *= 1_024;
        unit += 1;
    }
    if unit == 0 {
        return format!("{bytes} B");
    }

    let whole = bytes / divisor;
    let fraction = (bytes % divisor * 10 + divisor / 2) / divisor;
    let tenths = whole * 10 + fraction;
    format!("{}.{:01} {}", tenths / 10, tenths % 10, UNITS[unit])
}

#[cfg(test)]
mod tests {
    use crucksware::{
        error::Side,
        model::Category,
        progress::{ProgressEvent, ProgressPhase},
    };

    use super::{ProgressRenderer, ProgressState};

    #[test]
    fn renderer_is_not_created_when_stderr_is_not_a_terminal() {
        assert!(ProgressRenderer::for_terminal(false).is_none());
    }

    #[test]
    fn status_uses_only_reported_counts_and_bytes() {
        let mut state = ProgressState::default();
        state.observe(ProgressEvent::PhaseStarted {
            phase: ProgressPhase::Inventory(Side::Old),
            total: None,
        });
        state.observe(ProgressEvent::EntryDiscovered {
            side: Side::Old,
            entries: 1_024,
        });
        assert_eq!(
            state.message().as_deref(),
            Some("Indexing old: 1,024 entries")
        );

        state.observe(ProgressEvent::PhaseStarted {
            phase: ProgressPhase::Comparing,
            total: None,
        });
        assert_eq!(
            state.message().as_deref(),
            Some("Counting paths | 0 B read | 0 changes found")
        );
        state.observe(ProgressEvent::PhaseTotalKnown {
            phase: ProgressPhase::Comparing,
            total: 12_481,
        });
        state.observe(ProgressEvent::PhaseProgress {
            phase: ProgressPhase::Comparing,
            completed: 8_921,
            total: 12_481,
        });
        state.observe(ProgressEvent::BytesRead {
            total_bytes_read: 193_672_397,
        });
        for _ in 0..17 {
            state.observe(ProgressEvent::ChangeDiscovered {
                category: Category::Modified,
            });
        }

        assert_eq!(
            state.message().as_deref(),
            Some("Comparing 8,921 / 12,481 entries | 184.7 MiB read | 17 changes found")
        );
        assert!(!state.message().unwrap().contains('%'));

        state.observe(ProgressEvent::PhaseStarted {
            phase: ProgressPhase::Revalidation(Side::New),
            total: Some(12_482),
        });
        state.observe(ProgressEvent::PhaseProgress {
            phase: ProgressPhase::Revalidation(Side::New),
            completed: 2,
            total: 12_482,
        });
        assert_eq!(
            state.message().as_deref(),
            Some("Verifying new: 2 / 12,482 checks | 184.7 MiB read | 17 changes found")
        );
    }
}

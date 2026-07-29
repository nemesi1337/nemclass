//! One notification surface for the whole application.
//!
//! Messages used to go to eight independent `status_msg` / `last_error` fields,
//! one per panel, each rendered in its own corner of its own tab — so a message
//! from a panel you were not looking at was invisible, and none of them ever
//! expired. A scan error from twenty minutes ago sat there looking current.
//!
//! Panels keep their `status_msg` field as an **outbox**: they write to it as
//! before and [`Toasts::drain`] moves it here. That keeps the consolidation to
//! one place instead of rewriting every panel's error handling.

use std::time::{Duration, Instant};

use eframe::egui;

/// How long a message stays up before fading, by severity.
///
/// An error outlives an info message because it usually needs acting on, and a
/// user who looked away for ten seconds should still find out that a scan
/// failed.
const INFO_TTL: Duration = Duration::from_secs(4);
const WARNING_TTL: Duration = Duration::from_secs(8);
const ERROR_TTL: Duration = Duration::from_secs(20);

/// How long a toast spends fading out.
const FADE: Duration = Duration::from_millis(400);

/// The most toasts shown at once. Beyond this the oldest are dropped: a stack
/// taller than the window hides the newest message, which is the one that
/// matters.
const MAX_VISIBLE: usize = 6;

/// How severe a message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
    Error,
}

impl Level {
    fn ttl(self) -> Duration {
        match self {
            Level::Info => INFO_TTL,
            Level::Warning => WARNING_TTL,
            Level::Error => ERROR_TTL,
        }
    }

    fn colour(self) -> egui::Color32 {
        match self {
            Level::Info => egui::Color32::from_rgb(150, 190, 230),
            Level::Warning => egui::Color32::from_rgb(230, 190, 90),
            Level::Error => egui::Color32::from_rgb(235, 130, 120),
        }
    }

    fn glyph(self) -> &'static str {
        match self {
            Level::Info => "i",
            Level::Warning => "!",
            Level::Error => "✖",
        }
    }
}

#[derive(Debug, Clone)]
struct Toast {
    text: String,
    level: Level,
    born: Instant,
    /// Set when the same message arrives again, so a repeat is a count rather
    /// than a wall of identical rows.
    repeats: usize,
    /// Kept up until dismissed, whatever its age.
    pinned: bool,
}

/// The application's notification queue.
#[derive(Default)]
pub struct Toasts {
    items: Vec<Toast>,
}

impl Toasts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Post a message.
    ///
    /// An identical message still on screen bumps its counter and resets its
    /// clock instead of stacking: a freeze that fails every 200 ms would
    /// otherwise produce five identical toasts a second.
    pub fn push(&mut self, level: Level, text: impl Into<String>) {
        let text = text.into();
        if text.trim().is_empty() {
            return;
        }
        if let Some(existing) = self.items.iter_mut().find(|t| t.text == text) {
            existing.repeats += 1;
            existing.born = Instant::now();
            existing.level = level;
            return;
        }
        self.items.push(Toast {
            text,
            level,
            born: Instant::now(),
            repeats: 0,
            pinned: false,
        });
        // Oldest first, so trimming drops the stalest.
        while self.items.len() > MAX_VISIBLE {
            self.items.remove(0);
        }
    }

    pub fn info(&mut self, text: impl Into<String>) {
        self.push(Level::Info, text);
    }

    pub fn warn(&mut self, text: impl Into<String>) {
        self.push(Level::Warning, text);
    }

    pub fn error(&mut self, text: impl Into<String>) {
        self.push(Level::Error, text);
    }

    /// Take a panel's outbox field and post it, leaving the field empty.
    ///
    /// The level is inferred from the text rather than declared, because the
    /// panels write plain strings and threading a level through every one of
    /// them would be a much larger change for the same result.
    pub fn drain(&mut self, slot: &mut Option<String>) {
        let Some(text) = slot.take() else { return };
        let lower = text.to_lowercase();
        let level = if lower.contains("failed")
            || lower.contains("error")
            || lower.contains("cannot")
            || lower.contains("could not")
        {
            Level::Error
        } else if lower.contains("not ")
            || lower.contains("no ")
            || lower.contains("skipped")
            || lower.contains("truncat")
        {
            Level::Warning
        } else {
            Level::Info
        };
        self.push(level, text);
    }

    /// Draw the stack and drop whatever has expired.
    pub fn show(&mut self, ctx: &egui::Context) {
        let now = Instant::now();
        // Expired first, so a toast that ran out this frame is not drawn at full
        // opacity and then vanishes.
        self.items.retain(|t| {
            t.pinned || now.duration_since(t.born) < t.level.ttl() + FADE
        });
        if self.items.is_empty() {
            return;
        }

        let mut dismiss: Option<usize> = None;
        let mut pin: Option<usize> = None;

        egui::Area::new(egui::Id::new("nemclass_toasts"))
            .anchor(egui::Align2::RIGHT_BOTTOM, [-12.0, -12.0])
            .order(egui::Order::Foreground)
            .interactable(true)
            .show(ctx, |ui| {
                ui.set_max_width(460.0);
                // Newest at the bottom, nearest the corner the eye lands on.
                for (i, toast) in self.items.iter().enumerate() {
                    let age = now.duration_since(toast.born);
                    let alpha = if toast.pinned || age < toast.level.ttl() {
                        1.0
                    } else {
                        let fading = (age - toast.level.ttl()).as_secs_f32()
                            / FADE.as_secs_f32();
                        (1.0 - fading).clamp(0.0, 1.0)
                    };
                    let colour = toast.level.colour().gamma_multiply(alpha);

                    egui::Frame::popup(ui.style())
                        .fill(ui.visuals().panel_fill.gamma_multiply(alpha))
                        .stroke(egui::Stroke::new(1.0, colour))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.colored_label(colour, toast.level.glyph());
                                let mut text = toast.text.clone();
                                if toast.repeats > 0 {
                                    text.push_str(&format!("  (×{})", toast.repeats + 1));
                                }
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(text)
                                            .color(ui.visuals().text_color().gamma_multiply(alpha)),
                                    )
                                    .wrap(),
                                );
                                if ui
                                    .small_button(if toast.pinned { "📌" } else { "📍" })
                                    .on_hover_text("Keep this message up")
                                    .clicked()
                                {
                                    pin = Some(i);
                                }
                                if ui.small_button("✖").clicked() {
                                    dismiss = Some(i);
                                }
                            });
                        });
                }
            });

        if let Some(i) = pin
            && let Some(toast) = self.items.get_mut(i)
        {
            toast.pinned = !toast.pinned;
            toast.born = Instant::now();
        }
        if let Some(i) = dismiss {
            self.items.remove(i);
        }
        // Something is fading, so keep repainting until it is gone. Without this
        // a toast on an idle window would freeze mid-fade until the next input.
        if self.items.iter().any(|t| !t.pinned) {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identical_message_counts_up_instead_of_stacking() {
        let mut toasts = Toasts::new();
        for _ in 0..5 {
            toasts.error("Write failed at 0x1000");
        }
        assert_eq!(toasts.items.len(), 1, "a repeating failure is one row");
        assert_eq!(toasts.items[0].repeats, 4);
    }

    #[test]
    fn the_queue_is_bounded_and_drops_the_stalest() {
        let mut toasts = Toasts::new();
        for i in 0..MAX_VISIBLE + 3 {
            toasts.info(format!("message {i}"));
        }
        assert_eq!(toasts.items.len(), MAX_VISIBLE);
        // The newest survived; a stack taller than the window would hide it.
        assert_eq!(toasts.items.last().unwrap().text, format!("message {}", MAX_VISIBLE + 2));
    }

    #[test]
    fn draining_a_panel_slot_empties_it_and_infers_the_level() {
        let mut toasts = Toasts::new();
        let mut slot = Some("Read failed: no such process".to_string());
        toasts.drain(&mut slot);
        assert!(slot.is_none(), "the outbox is emptied, so it is not re-posted every frame");
        assert_eq!(toasts.items[0].level, Level::Error);

        toasts.drain(&mut Some("Scan truncated at the result limit".to_string()));
        assert_eq!(toasts.items[1].level, Level::Warning);

        toasts.drain(&mut Some("Saved to /tmp/project".to_string()));
        assert_eq!(toasts.items[2].level, Level::Info);
    }

    #[test]
    fn draining_an_empty_slot_posts_nothing() {
        let mut toasts = Toasts::new();
        toasts.drain(&mut None);
        toasts.drain(&mut Some("   ".to_string()));
        assert!(toasts.items.is_empty());
    }

    #[test]
    fn an_error_outlives_an_info_message() {
        assert!(Level::Error.ttl() > Level::Warning.ttl());
        assert!(Level::Warning.ttl() > Level::Info.ttl());
    }
}

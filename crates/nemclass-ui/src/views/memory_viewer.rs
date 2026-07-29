//! Cheat-Engine-style raw hex memory viewer panel.
//!
//! ## Layout
//! ```text
//! ┌─ Memory Viewer ──────────────────────────────────────────────────────────┐
//! │  [◀ Back]  Address: [0x00007fff…_________]  [Go]  Type: [Bytes ▼]       │
//! │  Region: libc-2.37.so  r--p                                              │
//! │  ──────────────────────────────────────────────────────────────────────  │
//! │  ┌─ Address ───────────┬─ 00 01 02 … 0F ──────────────────┬─ ASCII ───┐ │
//! │  │  0x00007fff0000     │  48 65 6C 6C 6F 20 57 6F 72 6C … │  Hello W… │ │
//! │  │  0x00007fff0010     │  64 21 00 00 00 00 00 00 00 00 … │  d!…      │ │
//! │  └─────────────────────┴──────────────────────────────────┴───────────┘ │
//! │  [Dissect as class here (TODO)]  [Disassemble here (TODO)]              │
//! └──────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Changed bytes since the last snapshot are tinted red.
//! String runs (ASCII / UTF-16LE) are highlighted in the ASCII column.
//! When the display type is Qword, each row group of 8 bytes is classified as
//! a pointer — clickable links navigate to the pointed-to address.

use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};

use nemclass_core::{
    AddrClass, Process, RegionIndex, StrKind, StringRun, classify_value, detect_strings,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Bytes-per-row choices. 16 is the default and what every hex editor uses;
/// 8 suits pointer-dense structures and 32 suits scanning for a pattern.
const BYTES_PER_ROW_CHOICES: [usize; 3] = [8, 16, 32];

/// How many bytes to snapshot around the current address (4 KiB page).
const SNAPSHOT_SIZE: usize = 4096;

/// Minimum ASCII / UTF-16 run length to be highlighted.
const MIN_STRING_LEN: usize = 4;

/// Interval between memory snapshots.
const SNAPSHOT_INTERVAL: Duration = Duration::from_millis(150);

/// Navigation history depth cap (avoids unbounded growth).
const HISTORY_CAP: usize = 64;

/// The most qwords one snapshot will classify.
///
/// `classify_value` issues a live read per pointer-looking slot plus a vtable
/// probe, so classifying a whole 4 KiB page is ~512 of those. Only the rows on
/// screen are ever looked at, so the window follows the viewport and this is
/// just the ceiling on how big that window may get.
const MAX_CLASSIFIED_QWORDS: usize = 256;

// ---------------------------------------------------------------------------
// Display type
// ---------------------------------------------------------------------------

/// How the hex dump group interprets each row of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DisplayType {
    Bytes,
    Word,
    Dword,
    Qword,
    Float32,
    Float64,
}

impl DisplayType {
    /// Human-readable combo label.
    fn label(self) -> &'static str {
        match self {
            Self::Bytes   => "Bytes",
            Self::Word    => "Word (u16)",
            Self::Dword   => "Dword (u32)",
            Self::Qword   => "Qword (u64)",
            Self::Float32 => "Float (f32)",
            Self::Float64 => "Double (f64)",
        }
    }

    /// Bytes per interpreted unit (used for grouping within a row).
    fn unit_size(self) -> usize {
        match self {
            Self::Bytes   => 1,
            Self::Word    => 2,
            Self::Dword   => 4,
            Self::Qword   => 8,
            Self::Float32 => 4,
            Self::Float64 => 8,
        }
    }
}

/// A named address the user marked, so a structure found once can be returned
/// to without re-deriving its address.
#[derive(Debug, Clone)]
pub struct Bookmark {
    pub address: usize,
    pub name: String,
}

// ---------------------------------------------------------------------------
// MemoryViewer
// ---------------------------------------------------------------------------

/// Raw hex memory viewer panel — analogous to `ScannerPanel` / `DebuggerPanel`.
///
/// Holds its own snapshot buffer so it can run independently of the class view.
pub struct MemoryViewer {
    // ── navigation ────────────────────────────────────────────────────────
    /// Current base address (the top-left byte of the visible hex grid).
    address: usize,
    /// Text the user is typing in the address bar.
    address_input: String,
    /// If `Some`, show a parse-error hint next to the Go button.
    address_error: Option<String>,
    /// Back-navigation stack (push on navigate, pop on Back).
    history: Vec<usize>,
    /// Forward stack, filled by Back so the jump can be undone. History was
    /// back-only: stepping back one page past what you wanted meant retyping
    /// the address.
    forward: Vec<usize>,
    /// Bytes shown per row.
    bytes_per_row: usize,
    /// Named addresses the user has marked, newest first.
    bookmarks: Vec<Bookmark>,
    /// Text for the "add bookmark" name field.
    bookmark_name: String,

    // ── selection and editing ─────────────────────────────────────────────
    /// The selected byte span as absolute addresses, inclusive of both ends.
    selection: Option<(usize, usize)>,
    /// The address a shift-click extends the selection from.
    selection_anchor: Option<usize>,
    /// The byte currently being typed over: its address and the text so far.
    editing: Option<(usize, String)>,
    /// Bytes copied out of the view, for Paste.
    ///
    /// Internal rather than the system clipboard because egui cannot read the
    /// system clipboard synchronously on every backend, and a paste that
    /// silently did nothing would be worse than one that only round-trips
    /// within the app. Copy also puts the hex on the system clipboard.
    clipboard: Vec<u8>,
    /// The byte value the Fill action writes.
    fill_text: String,
    /// The rows on screen last frame, so the pointer classification can follow
    /// the viewport instead of scanning the whole page.
    visible_rows: (usize, usize),

    // ── display type ──────────────────────────────────────────────────────
    display_type: DisplayType,

    // ── memory snapshot ───────────────────────────────────────────────────
    /// Latest snapshot buffer (`SNAPSHOT_SIZE` bytes starting at `address`).
    buf: Vec<u8>,
    /// Previous snapshot — used to detect changed bytes (red tint).
    prev_buf: Vec<u8>,
    /// Actual number of bytes successfully read (may be < `SNAPSHOT_SIZE`).
    bytes_read: usize,
    /// When the last snapshot was taken.
    last_snapshot: Option<Instant>,

    // ── string highlights ─────────────────────────────────────────────────
    /// String runs detected in the current `buf`.
    /// Per-qword pointer classification, refreshed once per snapshot rather
    /// than once per frame. See `refresh_qword_classes`.
    qword_classes: Vec<nemclass_core::PointerClass>,
    string_runs: Vec<StringRun>,

    // ── region index (Linux only at runtime, always compiled) ─────────────
    #[cfg(target_os = "linux")]
    region_index: Option<RegionIndex>,

    // ── status message ────────────────────────────────────────────────────
    pub status_msg: Option<String>,

    // ── disassemble request ───────────────────────────────────────────────
    /// Set when the user clicks "Disassemble here"; consumed by the parent via
    /// `take_disassemble_request()`.
    pending_disassemble: Option<usize>,

    // ── dissect request ───────────────────────────────────────────────────
    /// Set when the user clicks "Dissect as class here"; consumed by the parent
    /// via `take_dissect_request()`.  Carries the current viewer address.
    pending_dissect: Option<usize>,
}

impl MemoryViewer {
    pub fn new() -> Self {
        Self {
            address:        0,
            address_input:  String::new(),
            address_error:  None,
            history:        Vec::new(),
            forward:        Vec::new(),
            bytes_per_row:  16,
            bookmarks:      Vec::new(),
            bookmark_name:  String::new(),

            selection: None,
            selection_anchor: None,
            editing: None,
            clipboard: Vec::new(),
            fill_text: "00".to_string(),
            visible_rows: (0, 32),

            display_type: DisplayType::Bytes,

            buf:           vec![0u8; SNAPSHOT_SIZE],
            prev_buf:      vec![0u8; SNAPSHOT_SIZE],
            bytes_read:    0,
            last_snapshot: None,

            qword_classes: Vec::new(),
            string_runs: Vec::new(),

            #[cfg(target_os = "linux")]
            region_index: None,

            status_msg: None,
            pending_disassemble: None,
            pending_dissect: None,
        }
    }

    // -----------------------------------------------------------------------
    // Called from the parent on attach / detach
    // -----------------------------------------------------------------------

    /// Reset state when the user detaches or attaches to a new process.
    pub fn on_detach(&mut self) {
        self.buf      = vec![0u8; SNAPSHOT_SIZE];
        self.prev_buf = vec![0u8; SNAPSHOT_SIZE];
        self.bytes_read    = 0;
        self.last_snapshot = None;
        self.string_runs.clear();
        self.qword_classes.clear();
        self.history.clear();
        self.forward.clear();
        self.selection = None;
        self.selection_anchor = None;
        self.editing = None;
        self.address_error  = None;
        self.status_msg     = None;
        self.pending_disassemble = None;
        self.pending_dissect = None;

        #[cfg(target_os = "linux")]
        { self.region_index = None; }
    }

    /// Rebuild the `RegionIndex` from the attached process.
    /// No-op on non-Linux targets.
    pub fn on_attach(&mut self, process: &Process) {
        #[cfg(target_os = "linux")]
        {
            match RegionIndex::from_pid(process.pid()) {
                Ok(idx) => { self.region_index = Some(idx); }
                Err(e)  => {
                    self.status_msg = Some(format!("RegionIndex: {e}"));
                    self.region_index = None;
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = process; // suppress unused warning on Windows
    }

    // -----------------------------------------------------------------------
    // Disassemble-here request (consumed by parent NemclassApp)
    // -----------------------------------------------------------------------

    /// Returns the address to disassemble, if the user clicked the button this
    /// frame. Consumes the pending request (returns `None` on the next call).
    pub fn take_disassemble_request(&mut self) -> Option<usize> {
        self.pending_disassemble.take()
    }

    /// Returns the address to auto-dissect, if the user clicked "Dissect as
    /// class here" this frame.  Consumes the pending request.
    pub fn take_dissect_request(&mut self) -> Option<usize> {
        self.pending_dissect.take()
    }

    // -----------------------------------------------------------------------
    // Navigation helpers
    // -----------------------------------------------------------------------

    /// Public entry point to jump the hex view to `addr` (e.g. from a "follow
    /// pointer" action in the class view). Pushes the current address onto the
    /// back-navigation history.
    pub fn goto(&mut self, addr: usize) {
        self.navigate_to(addr);
    }

    fn navigate_to(&mut self, addr: usize) {
        if addr != self.address {
            // Push current address onto history (capped).
            if self.history.len() >= HISTORY_CAP {
                self.history.remove(0);
            }
            self.history.push(self.address);
            // A fresh jump forks the trail, so the forward branch is gone.
            self.forward.clear();
        }
        self.seek(addr);
    }

    /// Move without touching the history — paging and Back/Forward.
    fn seek(&mut self, addr: usize) {
        self.address       = addr;
        self.address_input = format!("{addr:#018x}");
        self.editing = None;
        // Force an immediate re-snapshot on next frame.
        self.last_snapshot = None;
    }

    fn navigate_back(&mut self) {
        if let Some(prev) = self.history.pop() {
            self.forward.push(self.address);
            self.seek(prev);
        }
    }

    fn navigate_forward(&mut self) {
        if let Some(next) = self.forward.pop() {
            if self.history.len() >= HISTORY_CAP {
                self.history.remove(0);
            }
            self.history.push(self.address);
            self.seek(next);
        }
    }

    /// Step the window by whole pages. Saturating at both ends: a wrap would
    /// silently teleport the view to the other end of the address space.
    fn page(&mut self, pages: isize) {
        let delta = SNAPSHOT_SIZE.saturating_mul(pages.unsigned_abs());
        let target = if pages < 0 {
            self.address.saturating_sub(delta)
        } else {
            self.address.saturating_add(delta)
        };
        if target != self.address {
            self.seek(target);
        }
    }

    // -----------------------------------------------------------------------
    // Snapshot logic
    // -----------------------------------------------------------------------

    fn maybe_snapshot(&mut self, process: &Process) {
        let due = self
            .last_snapshot
            .map(|t| t.elapsed() >= SNAPSHOT_INTERVAL)
            .unwrap_or(true);
        if !due {
            return;
        }

        // Rotate buffers.
        std::mem::swap(&mut self.buf, &mut self.prev_buf);

        // Ensure the buf is the right size.
        if self.buf.len() != SNAPSHOT_SIZE {
            self.buf = vec![0u8; SNAPSHOT_SIZE];
        }

        match process.read_buf(self.address, &mut self.buf) {
            Ok(n)  => {
                self.bytes_read = n;
                // Zero out any bytes past the short-read.
                for b in &mut self.buf[n..] { *b = 0; }
            }
            Err(e) => {
                self.bytes_read = 0;
                self.buf.fill(0);
                self.status_msg = Some(format!("Read failed: {e}"));
            }
        }

        // Detect string runs once per snapshot.
        self.string_runs = detect_strings(&self.buf[..self.bytes_read.min(SNAPSHOT_SIZE)], MIN_STRING_LEN);
        self.refresh_qword_classes(process);

        self.last_snapshot = Some(Instant::now());
    }

    /// Classify every qword in the snapshot as null / not-a-pointer / data /
    /// code / vtable, once per snapshot.
    ///
    /// This used to run in the draw path, so **every frame** classified up to
    /// 512 qwords — and `classify_value` issues a live read per pointer-looking
    /// slot, plus a vtable probe on top. That is hundreds of syscalls per frame
    /// on the UI thread, for a page of which only ~16 rows are visible. Doing it
    /// on the snapshot cadence (like `string_runs` above) is the same work at a
    /// fraction of the rate.
    #[cfg(target_os = "linux")]
    fn refresh_qword_classes(&mut self, process: &Process) {
        use nemclass_core::PointerClass;
        if self.display_type != DisplayType::Qword {
            self.qword_classes.clear();
            return;
        }
        let Some(idx) = self.region_index.as_ref() else {
            self.qword_classes.clear();
            return;
        };
        // Only the rows on screen are ever read, and each classification costs
        // a live read plus a vtable probe, so the window follows the viewport
        // rather than covering the whole page.
        let (first_row, last_row) = self.visible_rows;
        let per_row = self.bytes_per_row;
        let first_qword = first_row.saturating_mul(per_row) / 8;
        let last_qword = last_row
            .saturating_add(1)
            .saturating_mul(per_row)
            .div_ceil(8)
            .min(self.bytes_read / 8)
            .min(first_qword + MAX_CLASSIFIED_QWORDS);
        // Indexed by absolute qword, so the draw code can look a slot up
        // directly; slots outside the window stay `NotPointer`.
        self.qword_classes = vec![PointerClass::NotPointer; last_qword];
        for qi in first_qword..last_qword {
            let off = qi * 8;
            if off + 8 > self.buf.len() {
                continue;
            }
            let v = u64::from_le_bytes(self.buf[off..off + 8].try_into().unwrap_or([0u8; 8]));
            self.qword_classes[qi] = classify_value(v, idx, |addr, buf| process.read_buf(addr, buf));
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn refresh_qword_classes(&mut self, _process: &Process) {}

    // -----------------------------------------------------------------------
    // Main draw entry point
    // -----------------------------------------------------------------------

    /// Draw the full memory viewer panel.
    ///
    /// `process` is the currently attached process handle, or `None` when not
    /// attached.
    pub fn show(&mut self, ui: &mut egui::Ui, process: Option<&Process>) {
        if process.is_none() {
            ui.centered_and_justified(|ui| {
                ui.colored_label(
                    Color32::YELLOW,
                    "Attach to a process to view memory.",
                );
            });
            return;
        }
        let process = process.unwrap();

        // ── snapshot ─────────────────────────────────────────────────────
        self.maybe_snapshot(process);

        // ── top bar ──────────────────────────────────────────────────────
        self.show_top_bar(ui, process);
        ui.separator();

        // ── hex table ────────────────────────────────────────────────────
        self.show_hex_table(ui, process);

        // ── action buttons ────────────────────────────────────────────────
        ui.separator();
        ui.horizontal(|ui| {
            let addr = self.address;
            // "Dissect as class here" — Linux only at runtime; on other
            // platforms the button is shown disabled with a hover note.
            #[cfg(target_os = "linux")]
            {
                if ui.button("Dissect as class here").clicked() {
                    self.pending_dissect = Some(addr);
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                ui.add_enabled(false, egui::Button::new("Dissect as class here"))
                    .on_disabled_hover_text("Auto-dissect is Linux-only");
            }
            if ui.button("Disassemble here").clicked() {
                self.pending_disassemble = Some(addr);
            }
        });

        // ── status line ──────────────────────────────────────────────────
        if let Some(msg) = &self.status_msg.clone() {
            ui.add_space(4.0);
            ui.colored_label(Color32::from_rgb(220, 160, 40), msg);
        }
    }

    // -----------------------------------------------------------------------
    // Top bar: address input, Back, display-type combo, region info
    // -----------------------------------------------------------------------

    fn show_top_bar(&mut self, ui: &mut egui::Ui, process: &Process) {
        ui.horizontal(|ui| {
            // Back button.
            let can_back = !self.history.is_empty();
            if ui.add_enabled(can_back, egui::Button::new("◀ Back")).clicked() {
                self.navigate_back();
            }
            let can_forward = !self.forward.is_empty();
            if ui.add_enabled(can_forward, egui::Button::new("Forward ▶")).clicked() {
                self.navigate_forward();
            }

            ui.label("Address:");

            // Address text edit — initialize from current address if empty.
            if self.address_input.is_empty() {
                self.address_input = format!("{:#018x}", self.address);
            }

            let response = ui.add(
                egui::TextEdit::singleline(&mut self.address_input)
                    .desired_width(180.0)
                    .font(egui::TextStyle::Monospace),
            );

            let go_clicked = ui.button("Go").clicked();
            let enter_pressed = response.lost_focus()
                && ui.input(|i| i.key_pressed(egui::Key::Enter));

            if go_clicked || enter_pressed {
                self.try_parse_address();
            }

            // Show parse error hint in red.
            if let Some(err) = &self.address_error {
                ui.colored_label(Color32::RED, err);
            }

            ui.separator();

            // Display-type combo.
            ui.label("Type:");
            egui::ComboBox::from_id_salt("mem_viewer_display_type")
                .selected_text(self.display_type.label())
                .show_ui(ui, |ui| {
                    for dt in [
                        DisplayType::Bytes,
                        DisplayType::Word,
                        DisplayType::Dword,
                        DisplayType::Qword,
                        DisplayType::Float32,
                        DisplayType::Float64,
                    ] {
                        ui.selectable_value(&mut self.display_type, dt, dt.label());
                    }
                });

            ui.label("Width:");
            egui::ComboBox::from_id_salt("mem_viewer_row_width")
                .selected_text(self.bytes_per_row.to_string())
                .width(48.0)
                .show_ui(ui, |ui| {
                    for n in BYTES_PER_ROW_CHOICES {
                        ui.selectable_value(&mut self.bytes_per_row, n, n.to_string());
                    }
                });
        });

        self.show_edit_bar(ui, process);
        self.show_bookmark_bar(ui);

        // Region info line (platform-neutral classify path — always available).
        self.show_region_info(ui, process);
    }

    /// Selection actions: copy, paste, fill, and a pattern for the scanner.
    fn show_edit_bar(&mut self, ui: &mut egui::Ui, process: &Process) {
        let selection = self.selection_span();
        let has_selection = selection.is_some();

        let mut page_by = 0isize;
        ui.horizontal_wrapped(|ui| {
            // Paging: the window was a fixed 4 KiB and the only way past it was
            // to retype the address.
            if ui.button("◀ Page").on_hover_text("Back one page (PageUp)").clicked() {
                page_by = -1;
            }
            if ui.button("Page ▶").on_hover_text("Forward one page (PageDown)").clicked() {
                page_by = 1;
            }
            ui.separator();
            match selection {
                Some((start, len)) => {
                    ui.label(
                        RichText::new(format!("{len} byte(s) at {start:#x}")).monospace(),
                    );
                }
                None => {
                    ui.weak("click a byte to select; shift-click to extend");
                }
            }
            ui.separator();

            if ui
                .add_enabled(has_selection, egui::Button::new("Copy"))
                .on_hover_text("Copy the selected bytes as hex")
                .clicked()
                && let Some(bytes) = self.selected_bytes()
            {
                let hex = hex_string(&bytes);
                ui.ctx().copy_text(hex.clone());
                self.clipboard = bytes;
                self.status_msg = Some(format!("Copied {hex}"));
            }

            if ui
                .add_enabled(
                    has_selection && !self.clipboard.is_empty(),
                    egui::Button::new("Paste"),
                )
                .on_hover_text("Write the copied bytes over the selection")
                .clicked()
                && let Some((start, _)) = selection
            {
                let bytes = self.clipboard.clone();
                self.write_bytes(process, start, &bytes);
            }

            ui.add(
                egui::TextEdit::singleline(&mut self.fill_text)
                    .desired_width(28.0)
                    .font(egui::TextStyle::Monospace),
            );
            if ui
                .add_enabled(has_selection, egui::Button::new("Fill"))
                .on_hover_text("Write this byte over every byte of the selection")
                .clicked()
                && let Some((start, len)) = selection
            {
                match u8::from_str_radix(self.fill_text.trim(), 16) {
                    Ok(byte) => {
                        let bytes = vec![byte; len];
                        self.write_bytes(process, start, &bytes);
                    }
                    Err(_) => {
                        self.status_msg =
                            Some("Fill value must be two hex digits, e.g. 90.".into());
                    }
                }
            }

            if ui
                .add_enabled(has_selection, egui::Button::new("Copy as AOB"))
                .on_hover_text("Copy the selection as an array-of-bytes pattern for the scanner")
                .clicked()
                && let Some(bytes) = self.selected_bytes()
            {
                let pattern = hex_string(&bytes);
                ui.ctx().copy_text(pattern.clone());
                self.status_msg = Some(format!("AOB: {pattern}"));
            }

            if ui.add_enabled(has_selection, egui::Button::new("Clear")).clicked() {
                self.selection = None;
                self.selection_anchor = None;
            }
        });

        // Keyboard paging, but not while a byte is being typed over — the
        // keystroke belongs to the text field.
        if self.editing.is_none() && !super::typing_in_a_text_field(ui.ctx()) {
            ui.input(|i| {
                if i.key_pressed(egui::Key::PageUp) {
                    page_by = -1;
                } else if i.key_pressed(egui::Key::PageDown) {
                    page_by = 1;
                }
            });
        }
        if page_by != 0 {
            self.page(page_by);
        }
    }

    /// Bookmarks: name the current address, and jump back to a named one.
    fn show_bookmark_bar(&mut self, ui: &mut egui::Ui) {
        let mut goto: Option<usize> = None;
        let mut remove: Option<usize> = None;

        ui.horizontal_wrapped(|ui| {
            ui.label("Bookmark:");
            ui.add(
                egui::TextEdit::singleline(&mut self.bookmark_name)
                    .desired_width(110.0)
                    .hint_text("name"),
            );
            if ui.button("+").on_hover_text("Bookmark the current address").clicked() {
                let name = if self.bookmark_name.trim().is_empty() {
                    format!("{:#x}", self.address)
                } else {
                    self.bookmark_name.trim().to_string()
                };
                // Newest first: a bookmark just made is the one about to be used.
                self.bookmarks.insert(0, Bookmark { address: self.address, name });
                self.bookmark_name.clear();
            }
            for (i, bm) in self.bookmarks.iter().enumerate() {
                if ui
                    .small_button(&bm.name)
                    .on_hover_text(format!("{:#018x}", bm.address))
                    .clicked()
                {
                    goto = Some(bm.address);
                }
                if ui.small_button("✖").on_hover_text("Remove").clicked() {
                    remove = Some(i);
                }
            }
        });

        if let Some(addr) = goto {
            self.navigate_to(addr);
        }
        if let Some(i) = remove {
            self.bookmarks.remove(i);
        }
    }

    /// The selection as `(start address, length)`, if any.
    fn selection_span(&self) -> Option<(usize, usize)> {
        let (a, b) = self.selection?;
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        Some((lo, hi - lo + 1))
    }

    /// The selected bytes, read out of the current snapshot.
    fn selected_bytes(&self) -> Option<Vec<u8>> {
        let (start, len) = self.selection_span()?;
        let offset = start.checked_sub(self.address)?;
        let end = offset.checked_add(len)?;
        self.buf.get(offset..end.min(self.bytes_read)).map(<[u8]>::to_vec)
    }

    /// Write bytes into the target and refresh the view.
    ///
    /// A short write is reported rather than swallowed: a read-only page accepts
    /// the request and writes nothing, and a hex editor that shows the old value
    /// again with no explanation is the worst of both.
    fn write_bytes(&mut self, process: &Process, addr: usize, bytes: &[u8]) {
        match process.write_buf(addr, bytes) {
            Ok(n) if n == bytes.len() => {
                self.status_msg = Some(format!("Wrote {n} byte(s) at {addr:#x}"));
            }
            Ok(n) => {
                self.status_msg = Some(format!(
                    "Only {n} of {} byte(s) written at {addr:#x} — the page may be read-only.",
                    bytes.len()
                ));
            }
            Err(e) => {
                self.status_msg = Some(format!("Write failed at {addr:#x}: {e}"));
            }
        }
        // Show the result immediately rather than up to a snapshot interval later.
        self.last_snapshot = None;
    }

    /// Handle a click on the byte at `addr`, honouring the shift modifier.
    fn click_byte(&mut self, addr: usize, extend: bool) {
        match (extend, self.selection_anchor) {
            (true, Some(anchor)) => self.selection = Some((anchor, addr)),
            _ => {
                self.selection_anchor = Some(addr);
                self.selection = Some((addr, addr));
            }
        }
    }

    fn try_parse_address(&mut self) {
        // Shared with every other address box in the app — see
        // `super::parse_address`. This used to treat bare digits as decimal,
        // so `7fff0000` was rejected and `140000000` jumped somewhere else
        // entirely.
        match super::parse_address(&self.address_input) {
            Ok(addr) => {
                self.address_error = None;
                self.navigate_to(addr);
            }
            Err(e) => {
                self.address_error = Some(e);
            }
        }
    }

    fn show_region_info(&self, ui: &mut egui::Ui, _process: &Process) {
        // We build the region label from whatever index we have.
        // On Linux we have a live RegionIndex; on other platforms we show a
        // neutral message so the code compiles clean everywhere.
        let label: String = {
            #[cfg(target_os = "linux")]
            {
                match &self.region_index {
                    Some(idx) => {
                        match idx.classify(self.address) {
                            AddrClass::Unmapped => "Region: (unmapped)".to_owned(),
                            AddrClass::Data { module } => {
                                let m = module.as_deref().unwrap_or("anon");
                                format!("Region: {m}  r--p (data)")
                            }
                            AddrClass::Executable { module } => {
                                let m = module.as_deref().unwrap_or("anon");
                                format!("Region: {m}  r-xp (executable)")
                            }
                        }
                    }
                    None => "Region: (no index — attach to refresh)".to_owned(),
                }
            }
            #[cfg(not(target_os = "linux"))]
            { "Region: (not available on this platform)".to_owned() }
        };

        ui.horizontal(|ui| {
            ui.label(RichText::new(label).weak().monospace());
        });
    }

    // -----------------------------------------------------------------------
    // Hex table
    // -----------------------------------------------------------------------

    fn show_hex_table(&mut self, ui: &mut egui::Ui, process: &Process) {
        let text_height = ui.text_style_height(&egui::TextStyle::Monospace);
        let row_height  = text_height + 6.0;

        let bytes_per_row = self.bytes_per_row;
        let num_rows = SNAPSHOT_SIZE / bytes_per_row;

        // ── Pre-classify Qword values before entering the TableBuilder closure ──
        //
        // `classify_value` needs a `read` closure, which would require a
        // `&Process` borrow inside the `body.rows` callback — impossible while
        // `ui` is also borrowed.  We solve this by eagerly classifying every
        // Qword slot in the buffer here, where we still have `&Process`.
        //
        // `qword_classes[i]` is the classification of the u64 starting at byte
        // offset `i * 8` in `self.buf`.  Only populated when `display_type` is
        // Qword; stays empty otherwise to avoid unnecessary work.
        //
        // The type annotation is needed so the cfg-gated branches agree.
        // Computed once per snapshot in `refresh_qword_classes`, not per frame.
        use nemclass_core::PointerClass;
        let qword_classes: Vec<PointerClass> = self.qword_classes.clone();

        // Suppress the unused warning on non-Linux where process is only used above.
        #[cfg(not(target_os = "linux"))]
        let _ = process;

        // Snapshot the fields we'll need inside the closure.
        let base_addr    = self.address;
        let display_type = self.display_type;
        let bytes_read   = self.bytes_read;
        let buf          = self.buf.clone();
        let prev_buf     = self.prev_buf.clone();
        let string_runs  = self.string_runs.clone();

        // Accumulate any navigation request from pointer-click inside the table.
        let mut navigate_target: Option<usize> = None;
        // Interaction collected during the draw and applied after the closure
        // releases the borrow on `self`.
        let mut clicked_byte: Option<usize> = None;
        let mut begin_edit: Option<usize> = None;
        let mut edit_text: Option<String> = None;
        let mut commit_edit = false;
        let mut cancel_edit = false;
        let mut first_drawn = usize::MAX;
        let mut last_drawn = 0usize;
        let selection = self.selection_span().map(|(start, len)| (start, start + len - 1));
        let editing = self.editing.clone();
        let shift_held = ui.input(|i| i.modifiers.shift);

        TableBuilder::new(ui)
            .id_salt("mem_viewer_table")
            .striped(true)
            .resizable(true)
            .column(Column::initial(160.0).at_least(120.0))  // Address
            .column(Column::remainder().at_least(300.0))     // Hex bytes
            .column(Column::initial(140.0).at_least(80.0))  // ASCII / decoded
            .header(row_height, |mut header| {
                header.col(|ui| { ui.strong("Address"); });
                header.col(|ui| { ui.strong("Hex"); });
                header.col(|ui| { ui.strong("ASCII"); });
            })
            .body(|body| {
                body.rows(row_height, num_rows, |mut row| {
                    let row_idx    = row.index();
                    let buf_offset = row_idx * bytes_per_row;
                    let row_addr   = base_addr.wrapping_add(buf_offset);

                    // The viewport, so the next snapshot only classifies what
                    // is on screen.
                    first_drawn = first_drawn.min(row_idx);
                    last_drawn = last_drawn.max(row_idx);

                    // ── Address column ──────────────────────────────────────
                    row.col(|ui| {
                        ui.monospace(format!("{row_addr:#018x}"));
                    });

                    // ── Hex / interpreted column ────────────────────────────
                    row.col(|ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing.x = 4.0;

                            let unit = display_type.unit_size();
                            let mut b = 0usize;
                            while b < bytes_per_row {
                                let end   = (b + unit).min(bytes_per_row);
                                let buf_end = (buf_offset + end).min(buf.len());
                                let slice = if buf_offset + b < buf.len() {
                                    &buf[buf_offset + b .. buf_end]
                                } else {
                                    &[]
                                };

                                if slice.is_empty() { break; }

                                let changed = slice.iter().enumerate().any(|(i, &byte)| {
                                    let pi = buf_offset + b + i;
                                    pi < bytes_read && pi < prev_buf.len() && prev_buf[pi] != byte
                                });
                                let valid = buf_offset + b < bytes_read;

                                match display_type {
                                    DisplayType::Bytes => {
                                        let byte = slice[0];
                                        let addr = row_addr.wrapping_add(b);
                                        let color = if !valid {
                                            Color32::DARK_GRAY
                                        } else if changed {
                                            Color32::RED
                                        } else {
                                            Color32::LIGHT_GRAY
                                        };
                                        // Double-click types over the byte;
                                        // a single click selects it.
                                        if editing.as_ref().is_some_and(|(a, _)| *a == addr) {
                                            let mut text = editing
                                                .as_ref()
                                                .map(|(_, t)| t.clone())
                                                .unwrap_or_default();
                                            let resp = ui.add(
                                                egui::TextEdit::singleline(&mut text)
                                                    .desired_width(24.0)
                                                    .font(egui::TextStyle::Monospace),
                                            );
                                            resp.request_focus();
                                            edit_text = Some(text);
                                            if resp.lost_focus() {
                                                commit_edit = ui.input(|i| {
                                                    i.key_pressed(egui::Key::Enter)
                                                });
                                                cancel_edit = !commit_edit;
                                            }
                                        } else {
                                            let selected = selection
                                                .is_some_and(|(lo, hi)| addr >= lo && addr <= hi);
                                            let mut text = RichText::new(format!("{byte:02X}"))
                                                .monospace()
                                                .color(color);
                                            if selected {
                                                text = text
                                                    .background_color(Color32::from_rgb(60, 90, 130));
                                            }
                                            let resp = ui.add(
                                                egui::Label::new(text)
                                                    .sense(egui::Sense::click()),
                                            );
                                            if resp.double_clicked() {
                                                begin_edit = Some(addr);
                                            } else if resp.clicked() {
                                                clicked_byte = Some(addr);
                                            }
                                        }
                                    }
                                    DisplayType::Word if slice.len() >= 2 => {
                                        let v = u16::from_le_bytes([slice[0], slice[1]]);
                                        let color = if changed { Color32::RED } else { Color32::LIGHT_GRAY };
                                        ui.label(
                                            RichText::new(format!("{v:04X}")).monospace().color(color),
                                        );
                                    }
                                    DisplayType::Dword if slice.len() >= 4 => {
                                        let v = u32::from_le_bytes(slice[..4].try_into().unwrap());
                                        let color = if changed { Color32::RED } else { Color32::LIGHT_GRAY };
                                        ui.label(
                                            RichText::new(format!("{v:08X}")).monospace().color(color),
                                        );
                                    }
                                    DisplayType::Qword if slice.len() >= 8 => {
                                        let v = u64::from_le_bytes(slice[..8].try_into().unwrap());
                                        let color = if changed { Color32::RED } else { Color32::LIGHT_GRAY };

                                        // Look up the pre-classified pointer class for this
                                        // Qword slot.  Index = byte-offset / 8.
                                        let qword_idx = (buf_offset + b) / 8;
                                        let pc_opt = qword_classes.get(qword_idx).cloned();

                                        match pc_opt {
                                            Some(PointerClass::DataPtr) => {
                                                let label = format!("{v:016X}  →data");
                                                if ui.add(
                                                    egui::Button::new(
                                                        RichText::new(label)
                                                            .monospace()
                                                            .color(Color32::from_rgb(140, 200, 140)),
                                                    )
                                                    .frame(false),
                                                ).clicked() {
                                                    navigate_target = Some(v as usize);
                                                }
                                            }
                                            Some(PointerClass::CodePtr) => {
                                                let label = format!("{v:016X}  →code");
                                                if ui.add(
                                                    egui::Button::new(
                                                        RichText::new(label)
                                                            .monospace()
                                                            .color(Color32::from_rgb(255, 180, 100)),
                                                    )
                                                    .frame(false),
                                                ).clicked() {
                                                    navigate_target = Some(v as usize);
                                                }
                                            }
                                            Some(PointerClass::VTablePtr { method_count }) => {
                                                let label = format!("{v:016X}  →vtable[{method_count}]");
                                                if ui.add(
                                                    egui::Button::new(
                                                        RichText::new(label)
                                                            .monospace()
                                                            .color(Color32::from_rgb(140, 200, 255)),
                                                    )
                                                    .frame(false),
                                                ).clicked() {
                                                    navigate_target = Some(v as usize);
                                                }
                                            }
                                            Some(PointerClass::Null) => {
                                                ui.label(
                                                    RichText::new(format!("{v:016X}  null"))
                                                        .monospace()
                                                        .color(Color32::DARK_GRAY),
                                                );
                                            }
                                            _ => {
                                                // NotPointer or no index available.
                                                ui.label(
                                                    RichText::new(format!("{v:016X}")).monospace().color(color),
                                                );
                                            }
                                        }
                                    }
                                    DisplayType::Float32 if slice.len() >= 4 => {
                                        let v = f32::from_le_bytes(slice[..4].try_into().unwrap());
                                        let color = if changed { Color32::RED } else { Color32::LIGHT_GRAY };
                                        ui.label(
                                            RichText::new(format!("{v:.6}")).monospace().color(color),
                                        );
                                    }
                                    DisplayType::Float64 if slice.len() >= 8 => {
                                        let v = f64::from_le_bytes(slice[..8].try_into().unwrap());
                                        let color = if changed { Color32::RED } else { Color32::LIGHT_GRAY };
                                        ui.label(
                                            RichText::new(format!("{v:.10}")).monospace().color(color),
                                        );
                                    }
                                    _ => {
                                        // Partial row or unhandled unit — show raw bytes.
                                        for &byte in slice {
                                            ui.label(
                                                RichText::new(format!("{byte:02X}"))
                                                    .monospace()
                                                    .color(Color32::DARK_GRAY),
                                            );
                                        }
                                    }
                                }

                                b += unit;
                            }
                        });
                    });

                    // ── ASCII column ────────────────────────────────────────
                    row.col(|ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;

                            for byte_idx in 0..bytes_per_row {
                                let buf_pos = buf_offset + byte_idx;
                                if buf_pos >= buf.len() { break; }

                                let byte  = buf[buf_pos];
                                let valid = buf_pos < bytes_read;

                                let ch = if byte.is_ascii_graphic() || byte == b' ' {
                                    byte as char
                                } else {
                                    '.'
                                };

                                // String-run highlight.
                                let run = string_runs.iter().find(|r| {
                                    buf_pos >= r.offset && buf_pos < r.offset + r.len_bytes
                                });

                                let color = if !valid {
                                    Color32::DARK_GRAY
                                } else if let Some(r) = run {
                                    match r.kind {
                                        StrKind::Ascii   => Color32::from_rgb(100, 220, 100), // green
                                        StrKind::Utf16Le => Color32::from_rgb(100, 180, 255), // cyan-blue
                                    }
                                } else {
                                    Color32::GRAY
                                };

                                let is_run_start = run.map(|r| r.offset == buf_pos).unwrap_or(false);
                                let resp = ui.label(RichText::new(ch.to_string()).monospace().color(color));
                                if is_run_start && let Some(r) = run {
                                    resp.on_hover_text(format!("{:?}: \"{}\"", r.kind, r.text));
                                }
                            }
                        });
                    });
                });
            });

        if first_drawn != usize::MAX {
            self.visible_rows = (first_drawn, last_drawn);
        }
        if let Some(text) = edit_text
            && let Some((_, stored)) = self.editing.as_mut()
        {
            *stored = text;
        }
        if let Some(addr) = begin_edit {
            let offset = addr.wrapping_sub(self.address);
            let current = self.buf.get(offset).copied().unwrap_or(0);
            self.editing = Some((addr, format!("{current:02X}")));
            self.selection = Some((addr, addr));
            self.selection_anchor = Some(addr);
        } else if commit_edit {
            if let Some((addr, text)) = self.editing.take() {
                match u8::from_str_radix(text.trim(), 16) {
                    Ok(byte) => self.write_bytes(process, addr, &[byte]),
                    Err(_) => {
                        self.status_msg =
                            Some(format!("'{text}' is not a byte — expected two hex digits."));
                    }
                }
            }
        } else if cancel_edit {
            self.editing = None;
        }
        if let Some(addr) = clicked_byte {
            self.click_byte(addr, shift_held);
        }

        // Apply any navigation queued during the table draw (pointer-click follow).
        if let Some(target) = navigate_target {
            self.navigate_to(target);
            // Refresh the region index after jumping so the region label updates.
            // `process` is still live in this function scope; on non-Linux it was
            // suppressed above but the `if let Some(target)` branch is also only
            // meaningful on Linux where we have a real region index.
            #[cfg(target_os = "linux")]
            if let Ok(idx) = RegionIndex::from_pid(process.pid()) {
                self.region_index = Some(idx);
            }
        }
    }
}

/// Space-separated uppercase hex — the spelling every AOB scanner accepts,
/// including this one's own `BytePattern::parse`.
fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

impl Default for MemoryViewer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn viewer_at(addr: usize, bytes: &[u8]) -> MemoryViewer {
        let mut v = MemoryViewer::new();
        v.address = addr;
        v.buf = vec![0u8; SNAPSHOT_SIZE];
        v.buf[..bytes.len()].copy_from_slice(bytes);
        v.bytes_read = bytes.len();
        v
    }

    #[test]
    fn a_shift_click_extends_the_selection_from_the_anchor() {
        let mut v = viewer_at(0x1000, &[1, 2, 3, 4, 5, 6, 7, 8]);
        v.click_byte(0x1002, false);
        assert_eq!(v.selection_span(), Some((0x1002, 1)));
        v.click_byte(0x1005, true);
        assert_eq!(v.selection_span(), Some((0x1002, 4)));
        // Backwards from the anchor selects the same span the other way round.
        v.click_byte(0x1000, true);
        assert_eq!(v.selection_span(), Some((0x1000, 3)));
    }

    #[test]
    fn a_plain_click_replaces_the_selection_and_moves_the_anchor() {
        let mut v = viewer_at(0x1000, &[0; 16]);
        v.click_byte(0x1002, false);
        v.click_byte(0x1008, true);
        assert_eq!(v.selection_span(), Some((0x1002, 7)));
        v.click_byte(0x100C, false);
        assert_eq!(v.selection_span(), Some((0x100C, 1)));
        v.click_byte(0x100E, true);
        assert_eq!(v.selection_span(), Some((0x100C, 3)), "extends from the new anchor");
    }

    #[test]
    fn the_selected_bytes_come_from_the_snapshot_at_the_right_offset() {
        let v = {
            let mut v = viewer_at(0x1000, &[0xDE, 0xAD, 0xBE, 0xEF, 0x11]);
            v.selection = Some((0x1001, 0x1003));
            v
        };
        assert_eq!(v.selected_bytes(), Some(vec![0xAD, 0xBE, 0xEF]));
        assert_eq!(hex_string(&v.selected_bytes().unwrap()), "AD BE EF");
    }

    #[test]
    fn a_selection_past_the_short_read_is_clamped_not_padded_with_zeros() {
        // The buffer is a full page but only five bytes were readable; a
        // selection running off the end must not hand back invented zeros.
        let mut v = viewer_at(0x1000, &[1, 2, 3, 4, 5]);
        v.selection = Some((0x1003, 0x1010));
        assert_eq!(v.selected_bytes(), Some(vec![4, 5]));
    }

    #[test]
    fn back_and_forward_walk_the_same_trail() {
        let mut v = MemoryViewer::new();
        v.navigate_to(0x1000);
        v.navigate_to(0x2000);
        v.navigate_to(0x3000);
        v.navigate_back();
        assert_eq!(v.address, 0x2000);
        v.navigate_back();
        assert_eq!(v.address, 0x1000);
        v.navigate_forward();
        assert_eq!(v.address, 0x2000);
        v.navigate_forward();
        assert_eq!(v.address, 0x3000);
        // Nothing further forward, and the address stays put.
        v.navigate_forward();
        assert_eq!(v.address, 0x3000);
    }

    #[test]
    fn a_fresh_jump_forks_the_trail_and_drops_the_forward_branch() {
        let mut v = MemoryViewer::new();
        v.navigate_to(0x1000);
        v.navigate_to(0x2000);
        v.navigate_back();
        assert_eq!(v.address, 0x1000);
        v.navigate_to(0x9000);
        v.navigate_forward();
        assert_eq!(v.address, 0x9000, "0x2000 is no longer on the trail");
    }

    #[test]
    fn paging_moves_by_a_whole_window_and_saturates_at_the_ends() {
        let mut v = MemoryViewer::new();
        v.seek(0x10000);
        v.page(1);
        assert_eq!(v.address, 0x10000 + SNAPSHOT_SIZE);
        v.page(-1);
        assert_eq!(v.address, 0x10000);
        // Paging back from near zero must not wrap to the top of the address
        // space.
        v.seek(0x10);
        v.page(-1);
        assert_eq!(v.address, 0);
        v.seek(usize::MAX - 8);
        v.page(1);
        assert_eq!(v.address, usize::MAX);
    }

    #[test]
    fn paging_does_not_pile_up_history_entries() {
        let mut v = MemoryViewer::new();
        v.navigate_to(0x1000);
        let depth = v.history.len();
        for _ in 0..10 {
            v.page(1);
        }
        assert_eq!(v.history.len(), depth, "scrolling is not navigation");
    }

    #[test]
    fn hex_string_is_the_spelling_the_aob_scanner_parses() {
        let text = hex_string(&[0x48, 0x89, 0xE5, 0x00]);
        assert_eq!(text, "48 89 E5 00");
        let pattern = nemclass_scan::BytePattern::parse(&text).expect("parses as an AOB");
        assert_eq!(pattern.len(), 4);
    }
}

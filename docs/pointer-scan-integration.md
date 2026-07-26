# Pointer-scan integration checklist (post JS-API pass)

The pointer-scan **engine** (`crates/nemclass-scan/src/pointerscan.rs`) and a
self-contained **panel** (`crates/nemclass-ui/src/views/pointer_scan_panel.rs`)
are done and tested. Remaining wiring (do AFTER the JS-API expansion lands, to
avoid `mod.rs` conflicts):

## UI wiring (`nemclass-ui`)
1. `views/mod.rs`: add `mod pointer_scan_panel;` and
   `use pointer_scan_panel::{PointerScanPanel, PointerScanAction};`.
2. Add field `pointer_scan_panel: PointerScanPanel` to `NemclassApp` + init in `new()`.
3. `views/dock.rs`: add a `TabKind::PointerScan` variant + title "Pointer scan" +
   dispatch in the `DockViewer` to call the panel's `show()`.
4. In the tab body, call:
   ```rust
   let modules = self.process.as_ref().and_then(|p| p.modules().ok())
       .map(|it| it.collect::<Vec<_>>()).unwrap_or_default();
   let action = self.pointer_scan_panel.show(ui, self.process.as_ref(),
       self.process.as_ref().map(|p| p.pid()), &modules);
   ```
   Collect `action` into a `pending_*` field (draw-borrow safety) and apply after:
   - `PointerScanAction::CreateClass{formula, ..}` → `blank_class(&self.project)`,
     set its `address_formula = formula`, `add_class`, select it.
   - `PointerScanAction::Goto(addr)` → `pending_focus = Memory` + `memory_viewer.goto(addr)` (cfg linux).
5. On detach, call `self.pointer_scan_panel.on_detach()`.
6. Optional: a "Pointer-scan this address" button in the scanner results + class
   view pointer rows that seeds `set_goal(addr)` and focuses the tab.

## JS API (add pointer scan to the catalog)
Add to the `HOST_METHODS` catalog + `UiHostApi::call` dispatch:
- `scan.pointer(goal, opts?:{maxDepth?,maxOffset?}) -> {formula,base,depth}[]`
  Implement by building module static-ranges + `nemclass_scan::pointer_scan`, then
  `path.to_formula(module_name, module_base)` per hit (reuse the panel's module-owner lookup).
- `classes.fromPointer(goal, name?, opts?) -> uuid|null` — convenience: run a
  pointer scan, take the first/best path, create a class with that formula.

## Verify
- `cargo build --workspace` + `--features scripting`; clippy; `cargo test --workspace`.
- `pointer_scan_panel.rs` compiles (watch: `Label::truncate()` egui 0.35, `Column::remainder().at_least()` — both confirmed present).
- Manual: attach, enter a known heap address as goal, Scan, click "Class" → a class
  appears whose formula resolves back to the goal via "Try resolve"/live base.

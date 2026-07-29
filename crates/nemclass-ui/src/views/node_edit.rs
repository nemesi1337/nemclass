//! Class-view editing: the selection model, the undo history, the node
//! clipboard, and the deferred edit operations that mutate the project.
//!
//! Split out of `views/mod.rs` because this is where the ReClass workflow lives
//! and it was the part of that file that grew fastest. Everything here is pure
//! model mutation plus the small amount of state the class view needs to know
//! *what* to mutate; no drawing.
//!
//! ## Why edits are deferred
//!
//! Rows are drawn inside a `TableBuilder` body closure that holds `&mut self`.
//! An edit discovered mid-draw — a context-menu click, a committed text field —
//! cannot mutate the project from in there, so it is pushed onto
//! `pending_node_edits` and applied after the closure releases the borrow.

use std::collections::VecDeque;

use nemclass_model::{ClassNode, Node, Project};
use nemclass_model::serialize::NodeDef;
use uuid::Uuid;

use super::NemclassApp;

/// A node's identity within the project: which class owns it, and its index
/// path from that class's children.
pub(crate) type NodeRef = (Uuid, Vec<usize>);

// ---------------------------------------------------------------------------
// Edit operations
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) enum NodeEditOp {
    ChangeType { owner: Uuid, path: Vec<usize>, new_tag: &'static str },
    Delete { owner: Uuid, path: Vec<usize> },
    /// Remove `count` consecutive nodes starting at `path` (the toolbar's
    /// "Delete N fields"). Stops early at the end of the sibling list.
    DeleteRange { owner: Uuid, path: Vec<usize>, count: usize },
    AddBytes { owner: Uuid, path: Vec<usize>, count: usize },
    InsertBytes { owner: Uuid, path: Vec<usize>, count: usize },
    /// Append `count` bytes of Hex filler at the end of the class body. Used by
    /// the toolbar when no row is selected, so "Add 64" works on a fresh class.
    AppendBytes { owner: Uuid, count: usize },
    SetName { owner: Uuid, path: Vec<usize>, name: String },
    SetComment { owner: Uuid, path: Vec<usize>, comment: String },
    SetHidden { owner: Uuid, path: Vec<usize>, hidden: bool },
    SetPtrTarget { owner: Uuid, path: Vec<usize>, target: Option<Uuid> },
    SetInstance { owner: Uuid, path: Vec<usize>, target: Uuid },
    /// Insert previously copied nodes directly after `path` — or at the end of
    /// the class when `path` is empty.
    Paste { owner: Uuid, path: Vec<usize>, defs: Vec<NodeDef> },
    /// Move the selected nodes into a new class and leave a `ClassInstance` in
    /// their place. `paths` must all share a parent.
    ExtractClass { owner: Uuid, paths: Vec<Vec<usize>>, name: String },
}

impl NodeEditOp {
    /// Whether applying this shifts sibling indices, which invalidates any
    /// selection or path recorded before it.
    fn shifts_siblings(&self) -> bool {
        matches!(
            self,
            NodeEditOp::Delete { .. }
                | NodeEditOp::DeleteRange { .. }
                | NodeEditOp::AddBytes { .. }
                | NodeEditOp::InsertBytes { .. }
                | NodeEditOp::AppendBytes { .. }
                | NodeEditOp::Paste { .. }
                | NodeEditOp::ExtractClass { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// Which rows the class view has selected.
///
/// ReClass's every "…Node(s)" menu item is plural, and the workflow is
/// selecting eight rows and making them all `Int32`. A single `Option` could
/// not express that, so this holds a set plus the anchor a shift-click extends
/// from.
#[derive(Default, Clone)]
pub(crate) struct Selection {
    nodes: Vec<NodeRef>,
    anchor: Option<NodeRef>,
}

impl Selection {
    pub(crate) fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn contains(&self, owner: Uuid, path: &[usize]) -> bool {
        self.nodes.iter().any(|(o, p)| *o == owner && p.as_slice() == path)
    }

    /// The anchor — the row the toolbar's single-target actions apply to.
    pub(crate) fn anchor(&self) -> Option<&NodeRef> {
        self.anchor.as_ref().or_else(|| self.nodes.first())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &NodeRef> {
        self.nodes.iter()
    }

    pub(crate) fn clear(&mut self) {
        self.nodes.clear();
        self.anchor = None;
    }

    pub(crate) fn set_single(&mut self, node: NodeRef) {
        self.anchor = Some(node.clone());
        self.nodes = vec![node];
    }

    /// Ctrl+click: add or remove one row, leaving the rest alone.
    pub(crate) fn toggle(&mut self, node: NodeRef) {
        match self.nodes.iter().position(|n| *n == node) {
            Some(i) => {
                self.nodes.remove(i);
                if self.anchor.as_ref() == Some(&node) {
                    self.anchor = self.nodes.first().cloned();
                }
            }
            None => {
                self.anchor = Some(node.clone());
                self.nodes.push(node);
            }
        }
    }

    /// Shift+click: select everything between the anchor and `node`, in the
    /// order rows are displayed.
    ///
    /// `order` is the visible row list; the range is taken over *that*, not
    /// over sibling indices, so a range spanning an expanded container selects
    /// what the user actually sees between the two clicks.
    pub(crate) fn extend_to(&mut self, node: NodeRef, order: &[NodeRef]) {
        let Some(anchor) = self.anchor.clone() else {
            self.set_single(node);
            return;
        };
        let (Some(a), Some(b)) = (
            order.iter().position(|n| *n == anchor),
            order.iter().position(|n| *n == node),
        ) else {
            // One end is no longer visible (a container collapsed under it);
            // a range with an invisible endpoint is not what was asked for.
            self.set_single(node);
            return;
        };
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        self.nodes = order[lo..=hi].to_vec();
        self.anchor = Some(anchor);
    }

    pub(crate) fn select_all(&mut self, order: &[NodeRef]) {
        self.nodes = order.to_vec();
        self.anchor = order.first().cloned();
    }

    /// Move the selection one row up or down the visible list.
    ///
    /// `extend` keeps the anchor and grows the range, which is the shift+arrow
    /// behaviour; otherwise the selection collapses to the new row.
    pub(crate) fn step(&mut self, order: &[NodeRef], delta: isize, extend: bool) {
        if order.is_empty() {
            return;
        }
        let current = self
            .nodes
            .last()
            .and_then(|n| order.iter().position(|o| o == n))
            .unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, order.len() as isize - 1) as usize;
        let target = order[next].clone();
        if extend {
            self.extend_to(target, order);
        } else {
            self.set_single(target);
        }
    }

    /// Selected nodes that share `owner`, sorted so the *last* sibling comes
    /// first.
    ///
    /// Deletions and inserts shift every later index, so applying them
    /// back-to-front is the only order in which a multi-row edit leaves the
    /// remaining paths valid.
    pub(crate) fn paths_descending(&self, owner: Uuid) -> Vec<Vec<usize>> {
        let mut paths: Vec<Vec<usize>> = self
            .nodes
            .iter()
            .filter(|(o, _)| *o == owner)
            .map(|(_, p)| p.clone())
            .collect();
        paths.sort();
        paths.dedup();
        paths.reverse();
        paths
    }

    /// Drop anything no longer present in `order`.
    ///
    /// Called after an edit: a delete or a collapse can leave the selection
    /// pointing at rows that are gone, and acting on those would hit whatever
    /// shifted into their place.
    pub(crate) fn retain_visible(&mut self, order: &[NodeRef]) {
        self.nodes.retain(|n| order.contains(n));
        if let Some(anchor) = &self.anchor
            && !order.contains(anchor)
        {
            self.anchor = self.nodes.first().cloned();
        }
    }
}

// ---------------------------------------------------------------------------
// Undo history
// ---------------------------------------------------------------------------

/// How many undo steps are kept. Each is a serialized copy of the whole
/// project; at a few hundred kilobytes for a large one, sixty-four is a few
/// tens of megabytes at worst and covers far more than a session's worth of
/// mistakes.
const HISTORY_LIMIT: usize = 64;

/// Undo/redo over whole-project snapshots.
///
/// Snapshots rather than inverse operations: nodes are `Box<dyn Node>` and are
/// not `Clone`, so an inverse-op scheme would need every operation to be able to
/// reconstruct what it replaced — which is exactly the serialization this does
/// once, generically, for all of them. "Delete 1024 fields" and "Accept
/// auto-dissect" were previously irreversible.
#[derive(Default)]
pub(crate) struct EditHistory {
    undo: VecDeque<String>,
    redo: Vec<String>,
}

impl EditHistory {
    pub(crate) fn can_undo(&self) -> bool {
        !self.undo.is_empty()
    }

    pub(crate) fn can_redo(&self) -> bool {
        !self.redo.is_empty()
    }

    /// Record the state *before* a change. Clears the redo stack, because
    /// editing after undoing forks the history.
    fn push(&mut self, snapshot: String) {
        self.undo.push_back(snapshot);
        while self.undo.len() > HISTORY_LIMIT {
            self.undo.pop_front();
        }
        self.redo.clear();
    }

    fn take_undo(&mut self, current: String) -> Option<String> {
        let previous = self.undo.pop_back()?;
        self.redo.push(current);
        Some(previous)
    }

    fn take_redo(&mut self, current: String) -> Option<String> {
        let next = self.redo.pop()?;
        self.undo.push_back(current);
        Some(next)
    }

    pub(crate) fn clear(&mut self) {
        self.undo.clear();
        self.redo.clear();
    }
}

// ---------------------------------------------------------------------------
// NemclassApp editing methods
// ---------------------------------------------------------------------------

impl NemclassApp {
    /// Serialize the project for the undo stack.
    fn project_snapshot(&self) -> Option<String> {
        self.project.to_toml(&self.node_registry).ok()
    }

    /// Record the current project state so the next change can be undone.
    ///
    /// Silently does nothing if the project cannot be serialized. That is not a
    /// swallowed error: the same failure would already have surfaced on save,
    /// and refusing the *edit* because history could not be recorded would be a
    /// worse outcome than an edit that cannot be undone.
    pub(crate) fn record_undo(&mut self) {
        if let Some(snapshot) = self.project_snapshot() {
            self.history.push(snapshot);
        }
        self.mark_project_dirty();
    }

    pub(crate) fn mark_project_dirty(&mut self) {
        self.project_dirty = true;
    }

    /// Replace the project with a serialized snapshot, keeping the selected
    /// class if it still exists.
    fn restore_snapshot(&mut self, snapshot: &str) -> Result<(), String> {
        let restored = Project::from_toml(snapshot, &self.node_registry)
            .map_err(|e| format!("could not restore the project: {e}"))?;
        self.project = restored;
        if let Some(uuid) = self.selected_class
            && self.project.get_class(&uuid).is_none()
        {
            self.selected_class = self.project.classes_in_order().next().map(|c| c.uuid);
        }
        self.selection.clear();
        self.invalidate_class_view();
        Ok(())
    }

    pub(crate) fn undo(&mut self) {
        let Some(current) = self.project_snapshot() else { return };
        let Some(previous) = self.history.take_undo(current) else {
            self.toasts.info("Nothing to undo");
            return;
        };
        if let Err(e) = self.restore_snapshot(&previous) {
            self.toasts.error(e);
            return;
        }
        self.project_dirty = true;
        self.toasts.info("Undo");
    }

    pub(crate) fn redo(&mut self) {
        let Some(current) = self.project_snapshot() else { return };
        let Some(next) = self.history.take_redo(current) else {
            self.toasts.info("Nothing to redo");
            return;
        };
        if let Err(e) = self.restore_snapshot(&next) {
            self.toasts.error(e);
            return;
        }
        self.project_dirty = true;
        self.toasts.info("Redo");
    }

    /// Drop every cached view of the class body.
    pub(crate) fn invalidate_class_view(&mut self) {
        self.node_snapshots.clear();
        self.mem_buf.clear();
        self.edit_state = None;
        self.last_snapshot = None;
    }

    // -----------------------------------------------------------------------
    // Clipboard
    // -----------------------------------------------------------------------

    /// Serialize the selected nodes into the clipboard.
    pub(crate) fn copy_selection(&mut self) {
        let mut defs = Vec::new();
        // Ascending, so paste reproduces the order they appear in.
        let mut refs: Vec<NodeRef> = self.selection.iter().cloned().collect();
        refs.sort();
        for (owner, path) in &refs {
            if let Some(node) = resolve_node_ref(&self.project, *owner, path) {
                defs.push(self.node_registry.serialize_node_recursive(node));
            }
        }
        if defs.is_empty() {
            return;
        }
        self.status_msg = Some(format!("Copied {} field(s)", defs.len()));
        self.node_clipboard = defs;
    }

    pub(crate) fn cut_selection(&mut self) {
        self.copy_selection();
        self.delete_selection();
    }

    pub(crate) fn paste_clipboard(&mut self) {
        if self.node_clipboard.is_empty() {
            self.status_msg = Some("Clipboard is empty".to_string());
            return;
        }
        let Some(owner) = self.selected_class else { return };
        let path = self
            .selection
            .anchor()
            .filter(|(o, _)| *o == owner)
            .map(|(_, p)| p.clone())
            .unwrap_or_default();
        let defs = self.node_clipboard.clone();
        self.pending_node_edits.push(NodeEditOp::Paste { owner, path, defs });
    }

    pub(crate) fn delete_selection(&mut self) {
        let Some(owner) = self.selected_class else { return };
        // Back-to-front: every removal shifts the indices after it.
        for path in self.selection.paths_descending(owner) {
            self.pending_node_edits.push(NodeEditOp::Delete { owner, path });
        }
        self.selection.clear();
    }

    /// Apply one operation to every selected node.
    ///
    /// `make` receives each path; ops are queued back-to-front so that an
    /// operation which shifts siblings does not invalidate the paths still
    /// waiting behind it.
    pub(crate) fn apply_to_selection(
        &mut self,
        make: impl Fn(Uuid, Vec<usize>) -> NodeEditOp,
    ) {
        let Some(owner) = self.selected_class else { return };
        for path in self.selection.paths_descending(owner) {
            self.pending_node_edits.push(make(owner, path));
        }
    }

    /// Hide or reveal every selected node.
    pub(crate) fn set_selection_hidden(&mut self, hidden: bool) {
        self.apply_to_selection(move |owner, path| NodeEditOp::SetHidden { owner, path, hidden });
    }

    // -----------------------------------------------------------------------
    // Applying edits
    // -----------------------------------------------------------------------

    /// Apply every queued edit, recording one undo step for the batch.
    ///
    /// One step for the whole batch, not one per op: a multi-row type change is
    /// a single user action and undoing it row by row would be maddening.
    pub(crate) fn flush_pending_node_edits(&mut self) {
        if self.pending_node_edits.is_empty() {
            return;
        }
        self.record_undo();
        let ops = std::mem::take(&mut self.pending_node_edits);
        let mut shifted = false;
        for op in ops {
            shifted |= op.shifts_siblings();
            self.apply_node_edit_inner(op);
        }
        if shifted {
            // Paths recorded before the shift now name different nodes.
            self.selection.clear();
        }
    }

    /// Apply a single operation immediately, with its own undo step.
    pub(crate) fn apply_node_edit(&mut self, op: NodeEditOp) {
        self.record_undo();
        let shifted = op.shifts_siblings();
        self.apply_node_edit_inner(op);
        if shifted {
            self.selection.clear();
        }
    }

    fn apply_node_edit_inner(&mut self, op: NodeEditOp) {
        use nemclass_model::node::builtins::{ClassInstanceNode, PointerNode};

        let pointer_size = self.project.pointer_size();

        match op {
            NodeEditOp::ChangeType { owner, path, new_tag } => {
                if let Some((vec, idx)) = resolve_parent_vec_mut(&mut self.project, owner, &path)
                    && let Some(mut new_node) = self.node_registry.construct(new_tag)
                {
                    new_node.set_name(vec[idx].name().to_owned());
                    new_node.set_comment(vec[idx].comment().to_owned());
                    new_node.set_hidden(vec[idx].hidden());
                    new_node.set_pointer_size(pointer_size);
                    vec[idx] = new_node;
                }
            }
            NodeEditOp::Delete { owner, path } => {
                if let Some((vec, idx)) = resolve_parent_vec_mut(&mut self.project, owner, &path) {
                    vec.remove(idx);
                }
            }
            NodeEditOp::DeleteRange { owner, path, count } => {
                if let Some((vec, idx)) = resolve_parent_vec_mut(&mut self.project, owner, &path) {
                    // Clamp to the end of the sibling list: "delete 1024 fields"
                    // on a 12-field class removes the 12, not nothing.
                    let end = idx.saturating_add(count).min(vec.len());
                    vec.drain(idx..end);
                }
            }
            NodeEditOp::AppendBytes { owner, count } => {
                if let Some(class) = self.project.get_class_mut(&owner) {
                    class.children.extend(super::hex_fill(count));
                }
            }
            NodeEditOp::AddBytes { owner, path, count } => {
                if let Some((vec, idx)) = resolve_parent_vec_mut(&mut self.project, owner, &path) {
                    let insert_at = idx + 1;
                    for (j, node) in super::hex_fill(count).into_iter().enumerate() {
                        vec.insert(insert_at + j, node);
                    }
                }
            }
            NodeEditOp::InsertBytes { owner, path, count } => {
                if let Some((vec, idx)) = resolve_parent_vec_mut(&mut self.project, owner, &path) {
                    for (j, node) in super::hex_fill(count).into_iter().enumerate() {
                        vec.insert(idx + j, node);
                    }
                }
            }
            NodeEditOp::SetName { owner, path, name } => {
                if let Some(node) = resolve_node_mut(&mut self.project, owner, &path) {
                    node.set_name(name);
                }
            }
            NodeEditOp::SetComment { owner, path, comment } => {
                if let Some(node) = resolve_node_mut(&mut self.project, owner, &path) {
                    node.set_comment(comment);
                }
            }
            NodeEditOp::SetHidden { owner, path, hidden } => {
                if let Some(node) = resolve_node_mut(&mut self.project, owner, &path) {
                    node.set_hidden(hidden);
                }
            }
            NodeEditOp::SetPtrTarget { owner, path, target } => {
                if let Some((vec, idx)) = resolve_parent_vec_mut(&mut self.project, owner, &path) {
                    let mut node = PointerNode::new(vec[idx].name().to_owned());
                    node.set_comment(vec[idx].comment().to_owned());
                    node.set_hidden(vec[idx].hidden());
                    node.target_class_uuid = target;
                    // A node built outside `Project::add_class` never saw the
                    // project's target width, so hand it over explicitly.
                    node.set_pointer_size(pointer_size);
                    vec[idx] = Box::new(node);
                }
            }
            NodeEditOp::SetInstance { owner, path, target } => {
                if let Some((vec, idx)) = resolve_parent_vec_mut(&mut self.project, owner, &path) {
                    let mut new_node =
                        Box::new(ClassInstanceNode::new(vec[idx].name().to_owned(), target));
                    new_node.set_comment(vec[idx].comment().to_owned());
                    new_node.set_hidden(vec[idx].hidden());
                    vec[idx] = new_node;
                }
            }
            NodeEditOp::Paste { owner, path, defs } => {
                let mut nodes = Vec::with_capacity(defs.len());
                for def in defs {
                    match self.node_registry.deserialize_node(def) {
                        Ok(node) => nodes.push(node),
                        Err(e) => {
                            self.last_error = Some(format!("could not paste a field: {e}"));
                            return;
                        }
                    }
                }
                for node in nodes.iter_mut() {
                    node.set_pointer_size(pointer_size);
                }
                if path.is_empty() {
                    if let Some(class) = self.project.get_class_mut(&owner) {
                        class.children.extend(nodes);
                    }
                } else if let Some((vec, idx)) =
                    resolve_parent_vec_mut(&mut self.project, owner, &path)
                {
                    let at = idx + 1;
                    for (j, node) in nodes.into_iter().enumerate() {
                        vec.insert(at + j, node);
                    }
                }
            }
            NodeEditOp::ExtractClass { owner, paths, name } => {
                self.extract_class(owner, paths, name);
            }
        }

        self.invalidate_class_view();
    }

    /// Move `paths` out of `owner` into a fresh class, leaving a
    /// `ClassInstance` referring to it in their place.
    ///
    /// The nodes are serialized and re-built rather than moved, because taking
    /// them out of the parent's `Vec` and putting the placeholder back in one
    /// step needs an owned copy anyway.
    fn extract_class(&mut self, owner: Uuid, paths: Vec<Vec<usize>>, name: String) {
        // Only same-parent siblings can be replaced by one placeholder, and
        // only a contiguous run keeps the surrounding layout intact.
        let mut indices: Vec<usize> = Vec::new();
        let mut parent_path: Option<Vec<usize>> = None;
        for path in &paths {
            let Some((&last, parent)) = path.split_last() else { continue };
            match &parent_path {
                Some(existing) if existing != parent => {
                    self.last_error =
                        Some("Select fields with the same parent to make a class".to_string());
                    return;
                }
                Some(_) => {}
                None => parent_path = Some(parent.to_vec()),
            }
            indices.push(last);
        }
        indices.sort_unstable();
        indices.dedup();
        if indices.is_empty() {
            return;
        }
        if indices.last().unwrap() - indices[0] + 1 != indices.len() {
            self.last_error =
                Some("Select a contiguous run of fields to make a class".to_string());
            return;
        }

        let parent_path = parent_path.unwrap_or_default();
        let first = indices[0];
        let count = indices.len();

        // Serialize before removing: the defs are what the new class is built
        // from, and `Box<dyn Node>` cannot be cloned.
        let Some(siblings) = resolve_child_vec(&self.project, owner, &parent_path) else {
            return;
        };
        let defs: Vec<NodeDef> = siblings[first..first + count]
            .iter()
            .map(|n| self.node_registry.serialize_node_recursive(n.as_ref()))
            .collect();

        let mut new_class = ClassNode::new(if name.trim().is_empty() {
            "NewClass".to_string()
        } else {
            name.trim().to_string()
        });
        for def in defs {
            match self.node_registry.deserialize_node(def) {
                Ok(node) => new_class.children.push(node),
                Err(e) => {
                    self.last_error = Some(format!("could not build the class: {e}"));
                    return;
                }
            }
        }
        let new_uuid = new_class.uuid;
        let placeholder_name = new_class.name.to_lowercase();
        self.project.add_class(new_class);

        if let Some(vec) = resolve_child_vec_mut(&mut self.project, owner, &parent_path) {
            vec.drain(first..first + count);
            vec.insert(
                first,
                Box::new(nemclass_model::node::builtins::ClassInstanceNode::new(
                    placeholder_name,
                    new_uuid,
                )),
            );
        }
        self.selected_class = Some(new_uuid);
        self.status_msg = Some(format!("Extracted {count} field(s) into a new class"));
    }
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// The child list a path's *parent* names, plus the index within it.
pub(crate) fn resolve_parent_vec_mut<'a>(
    project: &'a mut Project,
    owner: Uuid,
    path: &[usize],
) -> Option<(&'a mut Vec<Box<dyn Node>>, usize)> {
    let (&last, parent) = path.split_last()?;
    let vec = resolve_child_vec_mut(project, owner, parent)?;
    if last < vec.len() { Some((vec, last)) } else { None }
}

/// The child list at `path`, walking down from the class.
pub(crate) fn resolve_child_vec_mut<'a>(
    project: &'a mut Project,
    owner: Uuid,
    path: &[usize],
) -> Option<&'a mut Vec<Box<dyn Node>>> {
    let class = project.get_class_mut(&owner)?;
    let mut vec = &mut class.children;
    for &idx in path {
        vec = vec.get_mut(idx)?.children_mut()?;
    }
    Some(vec)
}

fn resolve_child_vec<'a>(
    project: &'a Project,
    owner: Uuid,
    path: &[usize],
) -> Option<&'a [Box<dyn Node>]> {
    let class = project.get_class(&owner)?;
    let mut vec: &[Box<dyn Node>] = &class.children;
    for &idx in path {
        vec = vec.get(idx)?.children();
    }
    Some(vec)
}

pub(crate) fn resolve_node_mut<'a>(
    project: &'a mut Project,
    owner: Uuid,
    path: &[usize],
) -> Option<&'a mut Box<dyn Node>> {
    let (vec, idx) = resolve_parent_vec_mut(project, owner, path)?;
    vec.get_mut(idx)
}

pub(crate) fn resolve_node_ref<'a>(
    project: &'a Project,
    owner: Uuid,
    path: &[usize],
) -> Option<&'a dyn Node> {
    let (&last, parent) = path.split_last()?;
    let vec = resolve_child_vec(project, owner, parent)?;
    vec.get(last).map(|n| n.as_ref())
}

// ---------------------------------------------------------------------------
// The type menu
// ---------------------------------------------------------------------------

/// One group of node types in the "change type" menus.
pub(crate) struct TypeGroup {
    pub label: &'static str,
    pub types: &'static [(&'static str, &'static str)],
}

/// Every node type the class view can change a field to, grouped for menus.
///
/// The menu used to offer scalars, vectors and matrices only, so `Array`,
/// `Utf8Text`, `VTable`, `Function` and the rest existed in the model and in
/// saved projects but could not be reached from the UI at all.
pub(crate) const TYPE_GROUPS: &[TypeGroup] = &[
    TypeGroup {
        label: "Hex",
        types: &[
            ("Hex 8", "Hex8"),
            ("Hex 16", "Hex16"),
            ("Hex 32", "Hex32"),
            ("Hex 64", "Hex64"),
        ],
    },
    TypeGroup {
        label: "Signed",
        types: &[
            ("Int 8", "Int8"),
            ("Int 16", "Int16"),
            ("Int 32", "Int32"),
            ("Int 64", "Int64"),
            ("NInt (pointer-width)", "NInt"),
        ],
    },
    TypeGroup {
        label: "Unsigned",
        types: &[
            ("UInt 8", "UInt8"),
            ("UInt 16", "UInt16"),
            ("UInt 32", "UInt32"),
            ("UInt 64", "UInt64"),
            ("NUInt (pointer-width)", "NUInt"),
        ],
    },
    TypeGroup {
        label: "Float",
        types: &[("Float", "Float"), ("Double", "Double")],
    },
    TypeGroup {
        label: "Text",
        types: &[
            ("UTF-8 text", "Utf8Text"),
            ("UTF-16 text", "Utf16Text"),
            ("UTF-32 text", "Utf32Text"),
            ("UTF-8 text pointer", "Utf8TextPtr"),
            ("UTF-16 text pointer", "Utf16TextPtr"),
            ("UTF-32 text pointer", "Utf32TextPtr"),
        ],
    },
    TypeGroup {
        label: "Pointer",
        types: &[
            ("Pointer", "Pointer"),
            ("Function pointer", "FunctionPtr"),
            ("Function", "Function"),
            ("VTable", "VTable"),
        ],
    },
    TypeGroup {
        label: "Other",
        types: &[
            ("Bool", "Bool"),
            ("Bitfield", "BitField"),
            ("Enum", "Enum"),
            ("Union", "Union"),
            ("Array", "Array"),
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn node_ref(i: usize) -> NodeRef {
        (Uuid::nil(), vec![i])
    }

    fn order(n: usize) -> Vec<NodeRef> {
        (0..n).map(node_ref).collect()
    }

    #[test]
    fn a_shift_click_selects_the_visible_range_between_the_two_rows() {
        let order = order(10);
        let mut sel = Selection::default();
        sel.set_single(node_ref(2));
        sel.extend_to(node_ref(6), &order);
        assert_eq!(sel.len(), 5);
        for i in 2..=6 {
            assert!(sel.contains(Uuid::nil(), &[i]), "row {i} selected");
        }
        // The anchor stays put, so extending again re-ranges from the same row
        // rather than from the last click.
        sel.extend_to(node_ref(0), &order);
        assert_eq!(sel.len(), 3);
        assert!(sel.contains(Uuid::nil(), &[0]));
        assert!(sel.contains(Uuid::nil(), &[2]));
        assert!(!sel.contains(Uuid::nil(), &[6]));
    }

    #[test]
    fn a_ctrl_click_toggles_one_row_and_leaves_the_rest() {
        let mut sel = Selection::default();
        sel.set_single(node_ref(1));
        sel.toggle(node_ref(4));
        sel.toggle(node_ref(7));
        assert_eq!(sel.len(), 3);
        sel.toggle(node_ref(4));
        assert_eq!(sel.len(), 2);
        assert!(!sel.contains(Uuid::nil(), &[4]));
    }

    #[test]
    fn multi_row_paths_come_back_last_sibling_first() {
        let mut sel = Selection::default();
        sel.set_single(node_ref(1));
        sel.toggle(node_ref(5));
        sel.toggle(node_ref(3));
        // Deleting 1 before 5 would shift 5 to 4 and delete the wrong field, so
        // the order has to be descending.
        assert_eq!(sel.paths_descending(Uuid::nil()), vec![vec![5], vec![3], vec![1]]);
    }

    #[test]
    fn stepping_past_the_ends_clamps_rather_than_wrapping() {
        let order = order(3);
        let mut sel = Selection::default();
        sel.set_single(node_ref(0));
        sel.step(&order, -1, false);
        assert!(sel.contains(Uuid::nil(), &[0]), "stays on the first row");
        sel.step(&order, 5, false);
        assert!(sel.contains(Uuid::nil(), &[2]), "stops on the last row");
        assert_eq!(sel.len(), 1);
    }

    #[test]
    fn a_shift_arrow_grows_the_range_from_the_anchor() {
        let order = order(5);
        let mut sel = Selection::default();
        sel.set_single(node_ref(1));
        sel.step(&order, 1, true);
        sel.step(&order, 1, true);
        assert_eq!(sel.len(), 3);
        assert!(sel.contains(Uuid::nil(), &[1]));
        assert!(sel.contains(Uuid::nil(), &[3]));
    }

    #[test]
    fn rows_that_vanished_are_dropped_from_the_selection() {
        let mut sel = Selection::default();
        sel.select_all(&order(5));
        // Three rows were deleted.
        sel.retain_visible(&order(2));
        assert_eq!(sel.len(), 2);
        assert!(sel.anchor().is_some());
    }

    #[test]
    fn history_forgets_the_redo_branch_once_a_new_edit_lands() {
        let mut history = EditHistory::default();
        history.push("a".to_string());
        assert!(history.can_undo());
        let restored = history.take_undo("b".to_string()).unwrap();
        assert_eq!(restored, "a");
        assert!(history.can_redo());
        // Editing after an undo forks the timeline; the old redo is gone.
        history.push("c".to_string());
        assert!(!history.can_redo());
    }

    #[test]
    fn history_is_bounded() {
        let mut history = EditHistory::default();
        for i in 0..HISTORY_LIMIT + 20 {
            history.push(i.to_string());
        }
        assert_eq!(history.undo.len(), HISTORY_LIMIT);
        // The oldest were dropped, not the newest.
        assert_eq!(history.undo.back().unwrap(), &(HISTORY_LIMIT + 19).to_string());
    }
}

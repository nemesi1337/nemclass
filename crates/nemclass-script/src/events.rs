//! Event model for the lifecycle/scripting bus.
//!
//! Two kinds, because the user's requirement set mixes *notifications* with a
//! *query*:
//!
//! - [`Event`] — **fire-and-forget notifications** (`OnProjectLoad`, `OnAttach`,
//!   `OnDetach`, `ClassAddressUpdated`, `GlobalVariableUpdated`) plus a
//!   [`Event::Custom`] variant for user-raised events. Ported from ReClass.NET's
//!   `RemoteProcess` lifecycle events (`ProcessAttached` → [`Event::OnAttach`],
//!   `ProcessClosing`/`ProcessClosed` → [`Event::OnDetach`]).
//! - [`ClassAddressQuery`] — the **query hook** `TryResolveClassAddress`, which
//!   is *not* a notification: subscribers may each supply an address and the
//!   first `Some` wins (a resolver chain). It returns `Option<usize>` instead of
//!   being published, so it lives in its own type.
//!
//! ## Why identity-based payloads (not live objects)
//!
//! Every payload here is **serde-serializable** and refers to domain objects by
//! **stable identity** — a class [`Uuid`], a process `pid`, a project *path*, a
//! [`GlobalVariable`] `{ name, address }` — rather than borrowing live
//! `&Project` / `&Process` handles. This is deliberate: in M2 the JS engine runs
//! on a **dedicated v8 thread** and events are shipped across a channel and
//! serialized into JS. Borrowing live objects would make that boundary
//! impossible (lifetimes, `!Send` v8 isolates); identity + `serde` crosses it
//! cleanly, and the JS side looks up the live object through host APIs by id.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A global variable a script can name and address — a named pointer into the
/// target, mirroring ReClass.NET's `GlobalVariableUpdated` notion.
///
/// Identity-based like every other payload: it carries the resolved `address`
/// (a plain `usize`, so it survives the JS/serde boundary) rather than a live
/// memory handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalVariable {
    /// Script-facing name of the variable.
    pub name: String,
    /// Resolved absolute address in the target's address space.
    pub address: usize,
}

impl GlobalVariable {
    /// Convenience constructor.
    pub fn new(name: impl Into<String>, address: usize) -> Self {
        Self {
            name: name.into(),
            address,
        }
    }
}

/// A fire-and-forget notification published on the [`crate::EventBus`].
///
/// Subscribers observe these via [`crate::Subscriber::on_event`]; there is no
/// return value (unlike the [`ClassAddressQuery`] hook). All variants are
/// identity-based and `serde`-serializable so they cross the M2 v8-thread
/// boundary unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
pub enum Event {
    /// A project was loaded. Carries the project's on-disk *path* (a project is
    /// a directory — see the plan's project layout), not the live `Project`, so
    /// the payload is `Send`/serializable. Handlers re-open it via a host API.
    OnProjectLoad {
        /// Filesystem path to the loaded project directory.
        path: String,
    },

    /// Attached to a target process (ReClass.NET `ProcessAttached`). Carries the
    /// `pid` and best-effort process name, not the live `Process` handle.
    OnAttach {
        /// Process id now attached.
        pid: i32,
        /// Process name, if it could be resolved.
        name: Option<String>,
    },

    /// Detached from the current target (ReClass.NET `ProcessClosing` /
    /// `ProcessClosed`). No payload — there is no live process to describe.
    OnDetach,

    /// A class's resolved base address changed. Identifies the class by
    /// [`Uuid`] and reports the new address.
    ClassAddressUpdated {
        /// UUID of the affected class.
        class: Uuid,
        /// The class's newly resolved base address.
        address: usize,
    },

    /// A named global variable's address changed.
    GlobalVariableUpdated {
        /// The updated variable (name + new address).
        variable: GlobalVariable,
    },

    /// A periodic tick emitted once per snapshot interval, letting scripts do
    /// polling / freeze work without a timer of their own. Carries the attached
    /// `pid` (or `None` when not attached).
    OnTick {
        /// The attached process id, if any.
        pid: Option<i32>,
    },

    /// A script-registered global hotkey fired. Carries the registration `id`
    /// returned by `hotkeys.register`; scripts filter on it in their handler.
    OnHotkey {
        /// The hotkey registration id (from `hotkeys.register`).
        id: u32,
    },

    /// A user-raised custom event (`EventBus::raise`). `payload` is arbitrary
    /// serde JSON-shaped data (`serde_json::Value` in M2's JS bridge); modelled
    /// here as [`CustomPayload`] so the M1 crate needs no `serde_json` dep.
    Custom {
        /// User-defined event name.
        name: String,
        /// Opaque, serializable payload.
        payload: CustomPayload,
    },
}

impl Event {
    /// A short, stable discriminant string for this event — handy for logging
    /// and, in M2, for naming the JS handler dispatched to (`onAttach`, ...).
    pub fn kind(&self) -> &'static str {
        match self {
            Event::OnProjectLoad { .. } => "OnProjectLoad",
            Event::OnAttach { .. } => "OnAttach",
            Event::OnDetach => "OnDetach",
            Event::ClassAddressUpdated { .. } => "ClassAddressUpdated",
            Event::GlobalVariableUpdated { .. } => "GlobalVariableUpdated",
            Event::OnTick { .. } => "OnTick",
            Event::OnHotkey { .. } => "OnHotkey",
            Event::Custom { .. } => "Custom",
        }
    }
}

/// Opaque payload for [`Event::Custom`].
///
/// M1 has no `serde_json` dependency, so custom payloads are modelled as a
/// simple, serializable string map plus a free-form text field. In M2 this maps
/// directly onto `serde_json::Value` when the payload is handed to JS; keeping
/// it a distinct type means the M2 change is additive (add a `Json(Value)`
/// variant or a `From` impl) and does not alter this enum's shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomPayload {
    /// Free-form text payload (e.g. a JSON string, a message).
    pub text: String,
    /// Key/value string attributes.
    pub attrs: std::collections::BTreeMap<String, String>,
}

impl CustomPayload {
    /// An empty payload.
    pub fn empty() -> Self {
        Self::default()
    }

    /// A payload carrying just a text body.
    pub fn text(body: impl Into<String>) -> Self {
        Self {
            text: body.into(),
            attrs: Default::default(),
        }
    }
}

/// The `TryResolveClassAddress` **query hook**.
///
/// This is the one "event" that returns a value: subscribers form a resolver
/// **chain** and the first that yields `Some(address)` wins (see
/// [`crate::EventBus::resolve_class_address`]). It is kept separate from
/// [`Event`] precisely because it is a query, not a notification — publishing it
/// would discard the return value.
///
/// Identity-based like the rest: the process is named by `pid`, the class by
/// [`Uuid`]. A subscriber that recognises the class resolves the address itself
/// (through host APIs) and returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassAddressQuery {
    /// The attached process's pid.
    pub pid: i32,
    /// UUID of the class whose address is being resolved.
    pub class: Uuid,
}

impl ClassAddressQuery {
    /// Convenience constructor.
    pub fn new(pid: i32, class: Uuid) -> Self {
        Self { pid, class }
    }
}

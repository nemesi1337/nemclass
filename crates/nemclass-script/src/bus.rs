//! The event bus: registration, notification dispatch, and the
//! `TryResolveClassAddress` resolver chain.
//!
//! ## One subscriber trait for two worlds
//!
//! Both compile-time Rust [`crate::Plugin`]s *and* — in M2 — the JS
//! [`crate::ScriptEngine`] implement the **same** [`Subscriber`] trait, so the
//! bus treats them uniformly. This is the seam that lets M2's v8 engine plug in
//! without changing the bus contract: the engine is just another boxed
//! `Subscriber` whose `on_event` forwards into JS and whose
//! `try_resolve_class_address` calls a JS resolver.
//!
//! ## Threading (M1 vs M2)
//!
//! M1 is intentionally **single-threaded-simple**: the bus owns its subscribers
//! and dispatches inline on the caller's (UI) thread. In M2 the JS engine runs
//! on a **dedicated v8 thread** (v8 isolates are `!Send`); the engine's
//! `Subscriber` impl becomes a thin proxy that *serializes the [`Event`]* (all
//! payloads are `Serialize`) and sends it down a channel to that thread,
//! blocking for the reply only for [`Subscriber::try_resolve_class_address`]
//! (which must return a value). Nothing about `EventBus`'s public API changes —
//! the bridge lives entirely inside the engine's `Subscriber` impl.

use crate::events::{ClassAddressQuery, CustomPayload, Event};

/// A bus subscriber: a compile-time plugin or (M2) the JS engine.
///
/// Object-safe so the bus can hold `Box<dyn Subscriber>`. Both methods have
/// no-op defaults so implementors override only what they care about.
pub trait Subscriber {
    /// A stable name for this subscriber (diagnostics / ordering readability).
    fn name(&self) -> &str {
        "subscriber"
    }

    /// Handle a fire-and-forget [`Event`] notification. Default: ignore.
    fn on_event(&mut self, _event: &Event) {}

    /// Participate in the `TryResolveClassAddress` resolver chain.
    ///
    /// Return `Some(address)` to claim the resolution (short-circuiting the
    /// chain), or `None` to defer to later subscribers. Default: defer.
    fn try_resolve_class_address(&mut self, _query: &ClassAddressQuery) -> Option<usize> {
        None
    }
}

/// Central hub the app publishes lifecycle/custom events to and queries for
/// class addresses.
///
/// Subscribers are dispatched in **registration order**, which also fixes the
/// precedence of the [`EventBus::resolve_class_address`] chain (first
/// registered gets first refusal).
#[derive(Default)]
pub struct EventBus {
    subscribers: Vec<Box<dyn Subscriber>>,
}

impl EventBus {
    /// A bus with no subscribers.
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    /// Registers a subscriber, appending it to the dispatch/resolution order.
    pub fn register(&mut self, subscriber: Box<dyn Subscriber>) {
        self.subscribers.push(subscriber);
    }

    /// Number of registered subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Publishes a fire-and-forget notification to every subscriber, in
    /// registration order. No return value — this is for [`Event`]
    /// notifications only; use [`EventBus::resolve_class_address`] for the query
    /// hook.
    pub fn publish(&mut self, event: &Event) {
        for sub in &mut self.subscribers {
            sub.on_event(event);
        }
    }

    /// Runs the `TryResolveClassAddress` resolver chain: asks each subscriber in
    /// registration order and returns the **first `Some`** (short-circuiting).
    /// Returns `None` if no subscriber claims the class.
    pub fn resolve_class_address(&mut self, query: &ClassAddressQuery) -> Option<usize> {
        for sub in &mut self.subscribers {
            if let Some(addr) = sub.try_resolve_class_address(query) {
                return Some(addr);
            }
        }
        None
    }

    /// Raises a user-defined custom event, publishing it as
    /// [`Event::Custom`] to all subscribers.
    pub fn raise(&mut self, name: impl Into<String>, payload: CustomPayload) {
        let event = Event::Custom {
            name: name.into(),
            payload,
        };
        self.publish(&event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::GlobalVariable;
    use std::cell::RefCell;
    use std::rc::Rc;
    use uuid::Uuid;

    /// Records every event it sees into a shared log.
    struct Recorder {
        name: String,
        log: Rc<RefCell<Vec<String>>>,
    }

    impl Subscriber for Recorder {
        fn name(&self) -> &str {
            &self.name
        }
        fn on_event(&mut self, event: &Event) {
            self.log.borrow_mut().push(format!("{}:{}", self.name, event.kind()));
        }
    }

    /// Resolves a specific class UUID to a fixed address; defers otherwise.
    struct FixedResolver {
        wants: Uuid,
        addr: usize,
        /// Bumped every time this resolver is consulted, to prove
        /// short-circuiting.
        calls: Rc<RefCell<usize>>,
    }

    impl Subscriber for FixedResolver {
        fn try_resolve_class_address(&mut self, query: &ClassAddressQuery) -> Option<usize> {
            *self.calls.borrow_mut() += 1;
            if query.class == self.wants {
                Some(self.addr)
            } else {
                None
            }
        }
    }

    #[test]
    fn publish_fans_out_to_all_subscribers_in_order() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut bus = EventBus::new();
        bus.register(Box::new(Recorder {
            name: "a".into(),
            log: log.clone(),
        }));
        bus.register(Box::new(Recorder {
            name: "b".into(),
            log: log.clone(),
        }));

        bus.publish(&Event::OnAttach {
            pid: 1234,
            name: Some("target".into()),
        });
        bus.publish(&Event::OnDetach);

        assert_eq!(
            *log.borrow(),
            vec!["a:OnAttach", "b:OnAttach", "a:OnDetach", "b:OnDetach"]
        );
    }

    #[test]
    fn raise_publishes_a_custom_event() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut bus = EventBus::new();
        bus.register(Box::new(Recorder {
            name: "r".into(),
            log: log.clone(),
        }));

        bus.raise("my-event", CustomPayload::text("hello"));

        assert_eq!(*log.borrow(), vec!["r:Custom"]);
    }

    #[test]
    fn global_variable_updated_round_trips_as_event() {
        // Guards the identity-based payload shape used across the M2 boundary.
        let mut bus = EventBus::new();
        let log = Rc::new(RefCell::new(Vec::new()));
        bus.register(Box::new(Recorder {
            name: "r".into(),
            log: log.clone(),
        }));
        bus.publish(&Event::GlobalVariableUpdated {
            variable: GlobalVariable::new("g_health", 0xDEAD_BEEF),
        });
        assert_eq!(*log.borrow(), vec!["r:GlobalVariableUpdated"]);
    }

    #[test]
    fn resolve_class_address_returns_first_some() {
        let target = Uuid::new_v4();
        let other = Uuid::new_v4();
        let calls_a = Rc::new(RefCell::new(0));
        let calls_b = Rc::new(RefCell::new(0));

        let mut bus = EventBus::new();
        // First resolver only knows `other` -> defers for `target`.
        bus.register(Box::new(FixedResolver {
            wants: other,
            addr: 0x1000,
            calls: calls_a.clone(),
        }));
        // Second resolver knows `target` -> should win.
        bus.register(Box::new(FixedResolver {
            wants: target,
            addr: 0x2000,
            calls: calls_b.clone(),
        }));
        // Third resolver would also match `target`, but must never be asked
        // once the second short-circuits.
        let calls_c = Rc::new(RefCell::new(0));
        bus.register(Box::new(FixedResolver {
            wants: target,
            addr: 0x9999,
            calls: calls_c.clone(),
        }));

        let got = bus.resolve_class_address(&ClassAddressQuery::new(42, target));
        assert_eq!(got, Some(0x2000), "first Some in registration order wins");
        assert_eq!(*calls_a.borrow(), 1, "first resolver consulted");
        assert_eq!(*calls_b.borrow(), 1, "second resolver consulted and claimed");
        assert_eq!(*calls_c.borrow(), 0, "third resolver never reached (short-circuit)");
    }

    #[test]
    fn resolve_class_address_returns_none_when_unclaimed() {
        let mut bus = EventBus::new();
        bus.register(Box::new(FixedResolver {
            wants: Uuid::new_v4(),
            addr: 0x1000,
            calls: Rc::new(RefCell::new(0)),
        }));
        let got = bus.resolve_class_address(&ClassAddressQuery::new(1, Uuid::new_v4()));
        assert_eq!(got, None);
    }
}

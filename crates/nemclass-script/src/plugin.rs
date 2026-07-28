//! Compile-time plugins — the Rust analogue of ReClass.NET's
//! `Plugin` / `IPluginHost` / `PluginManager`.
//!
//! A [`Plugin`] is initialised with a [`PluginHost`] that grants access to the
//! registries it may extend (node types, providers, the event bus). This ports
//! ReClass.NET's contract: `Initialize(IPluginHost)` → [`Plugin::initialize`],
//! `Terminate()` → [`Plugin::terminate`], `GetCustomNodeTypes()` /
//! provider registration → the `register_*` host calls a plugin makes during
//! `initialize`. Behaviour, not structure, is ported: ReClass returns lists that
//! the manager installs; here a plugin registers *into* the host directly, which
//! is more idiomatic in Rust.

use nemclass_core::ProviderRegistry;
use nemclass_model::NodeRegistry;

use crate::bus::{EventBus, Subscriber};

/// The host handed to a [`Plugin`] during [`Plugin::initialize`].
///
/// Analogue of ReClass.NET's `IPluginHost` (which exposes the process, logger,
/// settings, etc.). M1 exposes exactly the extension points the plan calls for:
///
/// - a [`NodeRegistry`] to register **custom node types** into
///   (ReClass `GetCustomNodeTypes`);
/// - a [`ProviderRegistry`] to register **memory/process providers** into
///   (backend plugins);
/// - the [`EventBus`] to **subscribe** to lifecycle/custom events.
///
/// The host borrows these from the app for the duration of initialization, so a
/// plugin's `register_*` calls mutate the app's real registries.
pub struct PluginHost<'a> {
    /// Node-type registry — register custom node constructors/deserializers.
    pub nodes: &'a mut NodeRegistry,
    /// Provider registry — register custom memory/process backends.
    pub providers: &'a mut ProviderRegistry,
    /// The event bus — register [`Subscriber`]s for lifecycle/custom events.
    pub bus: &'a mut EventBus,
}

impl<'a> PluginHost<'a> {
    /// Builds a host over the app's registries and bus.
    pub fn new(
        nodes: &'a mut NodeRegistry,
        providers: &'a mut ProviderRegistry,
        bus: &'a mut EventBus,
    ) -> Self {
        Self {
            nodes,
            providers,
            bus,
        }
    }

    /// Convenience: register a bus [`Subscriber`] contributed by a plugin.
    pub fn subscribe(&mut self, subscriber: Box<dyn Subscriber>) {
        self.bus.register(subscriber);
    }
}

/// A compile-time plugin (discovered via Cargo features), ≈ ReClass.NET
/// `Plugin`.
///
/// Lifecycle: the app constructs the plugin, calls [`Plugin::initialize`] once
/// with a [`PluginHost`] (during which the plugin registers node types /
/// providers / event subscribers), and calls [`Plugin::terminate`] on shutdown.
pub trait Plugin {
    /// The plugin's stable name (for logging / registry keys).
    fn name(&self) -> &str;

    /// Called once at startup. The plugin registers its contributions into the
    /// [`PluginHost`]'s registries and subscribes to events. Returns an error
    /// string to abort loading this plugin.
    fn initialize(&mut self, host: &mut PluginHost<'_>) -> Result<(), String>;

    /// Called once at shutdown to release resources. Default: no-op.
    fn terminate(&mut self) {}
}

/// Owns the loaded compile-time plugins and drives their lifecycle, ≈
/// ReClass.NET's `PluginManager`.
///
/// Plugins are added (typically behind Cargo feature flags), then
/// [`PluginRegistry::initialize_all`] is called once with the app's registries
/// to wire every plugin in. On shutdown [`PluginRegistry::terminate_all`] tears
/// them down in reverse order.
#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<Box<dyn Plugin>>,
}

impl PluginRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Adds a plugin to be initialized. Feature-gated example wiring calls this
    /// (see [`register_builtin_plugins`]).
    pub fn add(&mut self, plugin: Box<dyn Plugin>) {
        self.plugins.push(plugin);
    }

    /// Number of registered plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether no plugins are registered.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// The registered plugin names, in load order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.plugins.iter().map(|p| p.name())
    }

    /// Initializes every plugin in load order against the app's registries and
    /// bus. Collects `(plugin_name, error)` for any plugin that fails, but keeps
    /// going (a failing plugin does not abort the others) — matching
    /// ReClass.NET's tolerant load.
    pub fn initialize_all(
        &mut self,
        nodes: &mut NodeRegistry,
        providers: &mut ProviderRegistry,
        bus: &mut EventBus,
    ) -> Vec<(String, String)> {
        let mut errors = Vec::new();
        for plugin in &mut self.plugins {
            let mut host = PluginHost::new(nodes, providers, bus);
            if let Err(e) = plugin.initialize(&mut host) {
                errors.push((plugin.name().to_owned(), e));
            }
        }
        errors
    }

    /// Terminates every plugin in reverse load order.
    pub fn terminate_all(&mut self) {
        for plugin in self.plugins.iter_mut().rev() {
            plugin.terminate();
        }
    }
}

/// Registers the plugins compiled into this build (feature-gated).
///
/// This is the discovery seam the plan calls for: each compile-time plugin lives
/// behind its own Cargo feature and is `add`ed here when enabled. With no plugin
/// features on, this is a no-op.
pub fn register_builtin_plugins(registry: &mut PluginRegistry) {
    let _ = registry; // silence unused when no plugin features are enabled
    #[cfg(feature = "example-plugin")]
    registry.add(Box::new(example::ExamplePlugin::default()));
}

/// A trivial example plugin proving the [`Plugin`] seam end-to-end. Gated behind
/// the `example-plugin` Cargo feature.
#[cfg(feature = "example-plugin")]
pub mod example {
    use super::*;
    use crate::events::{ClassAddressQuery, Event};

    /// Subscriber the example plugin installs: counts events it observes.
    #[derive(Default)]
    struct ExampleSubscriber {
        seen: std::sync::atomic::AtomicUsize,
    }

    impl Subscriber for ExampleSubscriber {
        fn name(&self) -> &str {
            "example-subscriber"
        }
        fn on_event(&mut self, _event: &Event) {
            self.seen
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        fn try_resolve_class_address(&mut self, _q: &ClassAddressQuery) -> Option<usize> {
            None
        }
    }

    /// The example plugin: on `initialize` it subscribes to the bus. That is
    /// enough to prove a compile-time plugin can reach every host extension
    /// point (it could equally register a node type or provider here).
    #[derive(Default)]
    pub struct ExamplePlugin {
        initialized: bool,
    }

    impl Plugin for ExamplePlugin {
        fn name(&self) -> &str {
            "example-plugin"
        }

        fn initialize(&mut self, host: &mut PluginHost<'_>) -> Result<(), String> {
            self.initialized = true;
            host.subscribe(Box::new(ExampleSubscriber::default()));
            Ok(())
        }

        fn terminate(&mut self) {
            self.initialized = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test plugin that subscribes and records that it was initialized.
    struct RecordingPlugin {
        initialized: bool,
    }

    struct CountingSub;
    impl Subscriber for CountingSub {
        fn name(&self) -> &str {
            "counting"
        }
    }

    impl Plugin for RecordingPlugin {
        fn name(&self) -> &str {
            "recording-plugin"
        }
        fn initialize(&mut self, host: &mut PluginHost<'_>) -> Result<(), String> {
            self.initialized = true;
            host.subscribe(Box::new(CountingSub));
            Ok(())
        }
        fn terminate(&mut self) {
            self.initialized = false;
        }
    }

    #[test]
    fn plugin_initializes_and_reaches_host_registries() {
        let mut nodes = NodeRegistry::new();
        let mut providers = ProviderRegistry::new();
        let mut bus = EventBus::new();

        let mut registry = PluginRegistry::new();
        registry.add(Box::new(RecordingPlugin { initialized: false }));
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.names().collect::<Vec<_>>(), vec!["recording-plugin"]);

        let errors = registry.initialize_all(&mut nodes, &mut providers, &mut bus);
        assert!(errors.is_empty(), "no plugin should fail");
        // The plugin subscribed to the bus during initialize.
        assert_eq!(bus.subscriber_count(), 1);

        registry.terminate_all();
    }

    #[test]
    fn failing_plugin_is_reported_but_others_continue() {
        struct FailPlugin;
        impl Plugin for FailPlugin {
            fn name(&self) -> &str {
                "fail"
            }
            fn initialize(&mut self, _host: &mut PluginHost<'_>) -> Result<(), String> {
                Err("boom".into())
            }
        }

        let mut nodes = NodeRegistry::new();
        let mut providers = ProviderRegistry::new();
        let mut bus = EventBus::new();

        let mut registry = PluginRegistry::new();
        registry.add(Box::new(FailPlugin));
        registry.add(Box::new(RecordingPlugin { initialized: false }));

        let errors = registry.initialize_all(&mut nodes, &mut providers, &mut bus);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, "fail");
        // The second (good) plugin still initialized and subscribed.
        assert_eq!(bus.subscriber_count(), 1);
    }

    #[cfg(feature = "example-plugin")]
    #[test]
    fn builtin_example_plugin_is_registered_and_initializes() {
        let mut registry = PluginRegistry::new();
        register_builtin_plugins(&mut registry);
        assert_eq!(registry.names().collect::<Vec<_>>(), vec!["example-plugin"]);

        let mut nodes = NodeRegistry::new();
        let mut providers = ProviderRegistry::new();
        let mut bus = EventBus::new();
        let errors = registry.initialize_all(&mut nodes, &mut providers, &mut bus);
        assert!(errors.is_empty());
        assert_eq!(bus.subscriber_count(), 1);
    }
}

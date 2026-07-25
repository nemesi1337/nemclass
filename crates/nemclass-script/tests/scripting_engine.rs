//! Integration test for the M2 `RustyScriptEngine` (v8), behind the `scripting`
//! feature. Run with `cargo test -p nemclass-script --features scripting`.
//!
//! This spins the engine (a dedicated v8 worker thread), loads inline JS modules,
//! and drives them through the [`ScriptEngine`] contract while a **mock**
//! [`HostApi`] stands in for the live process/project on the main thread.
//!
//! ## Why one test with one engine
//!
//! v8's platform is **process-global** and initializes once; spawning multiple
//! `RustyScriptEngine`s in a single test process crashes (SIGSEGV). The real app
//! only ever spawns one engine for its lifetime, so this test mirrors that: a
//! single engine exercises every behaviour (event dispatch → host bridge, and
//! the blocking class-address resolver for both the "returns a number" and
//! "defers to None" cases).

#![cfg(feature = "scripting")]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nemclass_script::engine::ScriptEngine;
use nemclass_script::events::{ClassAddressQuery, Event};
use nemclass_script::{HostApi, LogLevel, RustyScriptEngine};

/// Records everything scripts do through the host API, so the test can assert the
/// bridge actually reached the (main-thread) host.
#[derive(Default)]
struct MockHost {
    logs: Vec<String>,
    declared_classes: Vec<(String, String)>,
    declared_types: Vec<String>,
    pattern_calls: Vec<(String, String)>,
}

impl HostApi for MockHost {
    fn pattern_scan(&mut self, module: &str, pattern: &str) -> Result<Vec<usize>, String> {
        self.pattern_calls
            .push((module.to_string(), pattern.to_string()));
        // Deterministic fake result so the JS side can assert on it.
        Ok(vec![0x1000, 0x2000])
    }

    fn declare_type(
        &mut self,
        ty: nemclass_model::EnumDescription,
    ) -> Result<(), String> {
        self.declared_types.push(ty.name);
        Ok(())
    }

    fn declare_class(&mut self, name: &str, address_formula: &str) -> Result<(), String> {
        self.declared_classes
            .push((name.to_string(), address_formula.to_string()));
        Ok(())
    }

    fn log(&mut self, _level: LogLevel, msg: &str) {
        self.logs.push(msg.to_string());
    }
}

/// Pumps host requests until `cond(host)` holds or `timeout` elapses. The worker
/// (v8) thread blocks on host replies, so the test must service the bridge from
/// this (main) thread — exactly as the UI does each frame.
fn pump_until<F>(
    engine: &mut RustyScriptEngine,
    host: &Arc<Mutex<MockHost>>,
    timeout: Duration,
    mut cond: F,
) where
    F: FnMut(&MockHost) -> bool,
{
    let start = Instant::now();
    loop {
        {
            let mut h = host.lock().unwrap();
            engine.pump_host_requests(&mut *h);
            if cond(&h) {
                return;
            }
        }
        if start.elapsed() > timeout {
            let h = host.lock().unwrap();
            panic!(
                "condition not met within {timeout:?}; logs={:?} classes={:?} types={:?} scans={:?}",
                h.logs, h.declared_classes, h.declared_types, h.pattern_calls
            );
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn engine_dispatch_host_bridge_and_resolver() {
    let host = Arc::new(Mutex::new(MockHost::default()));
    let mut engine = RustyScriptEngine::spawn().expect("spawn v8 engine");

    // One script directory holding both an OnAttach handler (which drives all
    // four host fns) and a class-address resolver whose answer depends on the
    // query pid — letting a single handler cover both the "number" and "defer"
    // cases without a second engine.
    let attach_js = r#"
        nemclass.on("OnAttach", (e) => {
            nemclass.log("attached pid=" + e.pid);
            nemclass.declare_class("Player", '"game.exe"+0x10');
            nemclass.declare_type({ name: "Team", size: 4, use_flags: false, values: [["Red", 0], ["Blue", 1]] });
            const hits = nemclass.pattern_scan("game.exe", "48 8B ?? ??");
            nemclass.log("hits=" + hits.length);
        });
    "#;
    let resolver_js = r#"
        nemclass.on("tryResolveClassAddress", (q) => q.pid === 7 ? 0xDEAD : null);
    "#;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("attach.js"), attach_js).unwrap();
    std::fs::write(dir.path().join("resolver.js"), resolver_js).unwrap();
    engine.load_scripts(dir.path()).unwrap();

    // --- Event dispatch reaches every host fn ---------------------------------
    engine.on_event(&Event::OnAttach {
        pid: 4242,
        name: Some("game".into()),
    });
    pump_until(&mut engine, &host, Duration::from_secs(20), |h| {
        !h.declared_classes.is_empty()
            && !h.declared_types.is_empty()
            && !h.pattern_calls.is_empty()
            && h.logs.iter().any(|l| l.contains("hits=2"))
    });
    {
        let h = host.lock().unwrap();
        assert_eq!(
            h.declared_classes,
            vec![("Player".to_string(), "\"game.exe\"+0x10".to_string())]
        );
        assert_eq!(h.declared_types, vec!["Team".to_string()]);
        assert_eq!(
            h.pattern_calls,
            vec![("game.exe".to_string(), "48 8B ?? ??".to_string())]
        );
        // The event payload fields must reach the handler directly (e.pid, not
        // e.data.pid) — regression guard for the adjacently-tagged Event unwrap.
        assert!(h.logs.iter().any(|l| l.contains("attached pid=4242")));
        assert!(h.logs.iter().any(|l| l.contains("hits=2")));
    }

    // --- Resolver: returns a number when it claims the class ------------------
    let got = engine.resolve_class_address(&ClassAddressQuery::new(7, uuid::Uuid::nil()));
    assert_eq!(got, Some(0xDEAD));

    // --- Resolver: yields None when the handler defers (returns null) ---------
    let deferred = engine.resolve_class_address(&ClassAddressQuery::new(1, uuid::Uuid::nil()));
    assert_eq!(deferred, None);
}

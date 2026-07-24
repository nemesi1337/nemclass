//! Integration tests for the M2 `RustyScriptEngine` (v8), behind the `scripting`
//! feature. Run with `cargo test -p nemclass-script --features scripting`.
//!
//! These spin the engine (a dedicated v8 worker thread), load an inline JS
//! module, and drive it through the [`ScriptEngine`] contract while a **mock**
//! [`HostApi`] stands in for the live process/project on the main thread.

#![cfg(feature = "scripting")]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nemclass_script::engine::ScriptEngine;
use nemclass_script::events::{ClassAddressQuery, Event};
use nemclass_script::{HostApi, LogLevel, RustyScriptEngine};

/// Records everything scripts do through the host API, so tests can assert the
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
/// (v8) thread blocks on host replies, so a test must service the bridge from
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
fn dispatch_onattach_runs_handler_and_reaches_host_fns() {
    let host = Arc::new(Mutex::new(MockHost::default()));
    let mut engine = RustyScriptEngine::spawn().expect("spawn v8 engine");

    // A script that, on attach, logs and declares a class + a type + a scan.
    let script = r#"
        nemclass.on("OnAttach", (e) => {
            nemclass.log("attached pid=" + e.pid);
            nemclass.declare_class("Player", '"game.exe"+0x10');
            nemclass.declare_type({ name: "Team", size: 4, use_flags: false, values: [["Red", 0], ["Blue", 1]] });
            const hits = nemclass.pattern_scan("game.exe", "48 8B ?? ??");
            nemclass.log("hits=" + hits.length);
        });
    "#;

    // Write it into a temp `src/` and load the directory.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("attach.js"), script).unwrap();
    engine.load_scripts(dir.path()).unwrap();

    // Fire the event; the worker runs the handler which blocks on host replies.
    engine.on_event(&Event::OnAttach {
        pid: 4242,
        name: Some("game".into()),
    });

    // Service the bridge until the class + type + scan + logs have all landed.
    pump_until(&mut engine, &host, Duration::from_secs(20), |h| {
        !h.declared_classes.is_empty()
            && !h.declared_types.is_empty()
            && !h.pattern_calls.is_empty()
            && h.logs.iter().any(|l| l.contains("hits=2"))
    });

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
    assert!(h.logs.iter().any(|l| l.contains("attached pid=4242")));
    assert!(h.logs.iter().any(|l| l.contains("hits=2")));
}

#[test]
fn try_resolve_class_address_returns_number_from_js() {
    let host = Arc::new(Mutex::new(MockHost::default()));
    let mut engine = RustyScriptEngine::spawn().expect("spawn v8 engine");

    // A resolver that claims any class with a fixed address.
    let script = r#"
        nemclass.on("tryResolveClassAddress", (q) => 0xDEAD);
    "#;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("resolver.js"), script).unwrap();
    engine.load_scripts(dir.path()).unwrap();

    // `resolve_class_address` blocks the main thread on the worker reply. The
    // resolver does not call host fns, so no pumping is needed here.
    let got = engine.resolve_class_address(&ClassAddressQuery::new(7, uuid::Uuid::nil()));
    assert_eq!(got, Some(0xDEAD));

    // Sanity: a background pump drains any stray requests without hanging.
    let mut h = host.lock().unwrap();
    engine.pump_host_requests(&mut *h);
}

#[test]
fn resolver_that_defers_yields_none() {
    let mut engine = RustyScriptEngine::spawn().expect("spawn v8 engine");
    let script = r#"
        nemclass.on("tryResolveClassAddress", (q) => null);
    "#;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("defer.js"), script).unwrap();
    engine.load_scripts(dir.path()).unwrap();

    let got = engine.resolve_class_address(&ClassAddressQuery::new(1, uuid::Uuid::nil()));
    assert_eq!(got, None);
}

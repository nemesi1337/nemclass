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
    /// Generic catalog calls: `(method, args-json-string)`.
    generic_calls: Vec<(String, String)>,
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

    fn call(
        &mut self,
        method: &str,
        args: &nemclass_script::engine_rusty::serde_json::Value,
    ) -> Result<nemclass_script::engine_rusty::serde_json::Value, String> {
        self.generic_calls
            .push((method.to_string(), args.to_string()));
        // A known value for mem.readU32 so the JS side can assert the round-trip.
        match method {
            "mem.readU32" => Ok(nemclass_script::engine_rusty::serde_json::json!(0xCAFE_u32)),
            _ => Ok(nemclass_script::engine_rusty::serde_json::Value::Null),
        }
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
            // Generic catalog bridge: nemclass.mem.readU32 -> __host_call.
            const v = nemclass.mem.readU32(0x1000);
            nemclass.log("readU32=0x" + v.toString(16));
        });
    "#;
    let resolver_js = r#"
        nemclass.on("tryResolveClassAddress", (q) => q.pid === 7 ? 0xDEAD : null);
        // Member form advertised by nemclass.d.ts — must also be honored. Claims a
        // different pid so it can't collide with the `on(...)` resolver above.
        nemclass.tryResolveClassAddress = (q) => q.pid === 9 ? 0xBEEF : null;
    "#;

    // Multi-file import: a helper module imported *without* a file extension
    // (`./mathlib`, not `./mathlib.ts`) from another script. This exercises the
    // `RelativeImportResolver` — the default rustyscript loader would reject it
    // with `requested module is not loaded: ./mathlib`. The importer registers
    // an OnAttach handler so its effect (a log line) surfaces through the host.
    let helper_ts = r#"
        export function doubler(n: number): number { return n * 2; }
    "#;
    let importer_ts = r#"
        import { doubler } from "./mathlib";
        nemclass.on("OnAttach", () => {
            nemclass.log("doubled=" + doubler(21));
        });
    "#;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("attach.js"), attach_js).unwrap();
    std::fs::write(dir.path().join("resolver.js"), resolver_js).unwrap();
    std::fs::write(dir.path().join("mathlib.ts"), helper_ts).unwrap();
    std::fs::write(dir.path().join("importer.ts"), importer_ts).unwrap();
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
            && h.logs.iter().any(|l| l.contains("readU32=0xcafe"))
            && h.logs.iter().any(|l| l.contains("doubled=42"))
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

        // Generic catalog bridge: the mock received the exact method + args, and
        // the known return value (0xCAFE) round-tripped back into JS.
        assert!(
            h.generic_calls
                .iter()
                .any(|(m, a)| m == "mem.readU32" && a.contains("4096")),
            "generic __host_call reached the host: {:?}",
            h.generic_calls
        );
        assert!(h.logs.iter().any(|l| l.contains("readU32=0xcafe")));

        // Multi-file import worked: the extensionless `import { doubler } from
        // "./mathlib"` resolved and executed (21 * 2 == 42).
        assert!(
            h.logs.iter().any(|l| l.contains("doubled=42")),
            "extensionless relative import resolved and ran: {:?}",
            h.logs
        );
    }

    // --- Resolver: returns a number when it claims the class ------------------
    let got = engine.resolve_class_address(&ClassAddressQuery::new(7, uuid::Uuid::nil()));
    assert_eq!(got, Some(0xDEAD));

    // --- Resolver: the `nemclass.tryResolveClassAddress = ...` member form -----
    // (the `on(...)` resolver defers on pid 9, so the member form must answer.)
    let member = engine.resolve_class_address(&ClassAddressQuery::new(9, uuid::Uuid::nil()));
    assert_eq!(member, Some(0xBEEF));

    // --- Resolver: yields None when every resolver defers (returns null) -------
    let deferred = engine.resolve_class_address(&ClassAddressQuery::new(1, uuid::Uuid::nil()));
    assert_eq!(deferred, None);

    // --- Reload does not stack lifecycle handlers -----------------------------
    // Regression guard: reloading the same directory must clear the previous
    // generation's handlers (`__nemclass_reset`), so a subsequent OnAttach fires
    // the handler exactly once — not once per prior load. Before the fix, handlers
    // accumulated and OnAttach fired twice after a single reload. (Also guards the
    // reload path itself, which must not deadlock the v8 worker.)
    let classes_before = host.lock().unwrap().declared_classes.len();
    engine.load_scripts(dir.path()).unwrap();
    engine.on_event(&Event::OnAttach {
        pid: 555,
        name: Some("game".into()),
    });
    // Pump until the *last* effect of the OnAttach handlers for this dispatch —
    // importer.ts's "doubled=42" runs after attach.js's whole chain. Waiting for
    // an earlier effect would return while attach.js is still mid-handler (blocked
    // on an unanswered host call), leaving the worker unable to see `Shutdown`.
    // "doubled=42" is logged once per dispatch, so after the reload it appears a
    // second time.
    pump_until(&mut engine, &host, Duration::from_secs(20), |h| {
        h.logs.iter().filter(|l| l.contains("doubled=42")).count() >= 2
            && h.logs.iter().any(|l| l.contains("attached pid=555"))
    });
    let classes_after = host.lock().unwrap().declared_classes.len();
    assert_eq!(
        classes_after - classes_before,
        1,
        "reload must not stack OnAttach handlers (one declare_class per dispatch); \
         declared_classes={:?}",
        host.lock().unwrap().declared_classes
    );
}

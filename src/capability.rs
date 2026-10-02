//! Capability extension points — faithful port of `capability.hh` /
//! `capability.cc` (51 lines).
//!
//! Infrastructure for discovering code extensions to the decompiler. In C++,
//! this uses static initializers to auto-register extension singletons. In
//! Rust, we provide a `CapabilityRegistry` that extensions register with at
//! startup, and `initialize_all` calls `initialize()` on each registered
//! extension.
//!
//! This is the base system that `ArchitectureCapability` (arch.rs),
//! `PrintLanguageCapability` (printlanguage.rs), and other extension points
//! build upon.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/capability.{hh,cc}.

use std::sync::{Arc, Mutex};

/// Trait for automatically registering extension points to the decompiler.
/// Faithful to `CapabilityPoint` (capability.hh:39).
///
/// Each extension provides a type implementing this trait and registers a
/// singleton with the global [`CapabilityRegistry`]. The decompiler engine
/// then calls `initialize_all()` to let each extension complete its
/// integration.
pub trait CapabilityPoint: Send + Sync {
    // RUDRA-GLUE: initialize (no Ghidra counterpart found)
    /// Complete initialization of an extension point. This is implemented by
    /// each extension so it can do specialized integration. Faithful to
    /// `initialize` (capability.hh:49).
    fn initialize(&self);
}

/// The global registry of extension point singletons. Faithful to the static
/// `getList()` method of `CapabilityPoint` (capability.cc:24).
///
/// In C++, extensions register themselves during static initialization. In
/// Rust, extensions must explicitly call `register()` at startup (typically
/// from a constructor or init function).
pub struct CapabilityRegistry {
    points: Mutex<Vec<Arc<dyn CapabilityPoint>>>,
}

impl Default for CapabilityRegistry {
    // RUDRA-GLUE: default (no Ghidra counterpart found)
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityRegistry {
    // RUDRA-GLUE: new (no Ghidra counterpart found)
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            points: Mutex::new(Vec::new()),
        }
    }

    // RUDRA-GLUE: register (no Ghidra counterpart found)
    /// Register an extension point. Faithful to the `CapabilityPoint`
    /// constructor behavior (capability.cc:33) which auto-registers.
    pub fn register(&self, point: Arc<dyn CapabilityPoint>) {
        self.points.lock().unwrap().push(point);
    }

    // RUDRA-GLUE: initialize_all (no Ghidra counterpart found)
    /// Give all registered capabilities a chance to initialize. Faithful to
    /// `CapabilityPoint::initializeAll` (capability.cc:40). After calling
    /// `initialize()` on each extension, the list is cleared (matching Ghidra).
    pub fn initialize_all(&self) {
        let mut points = self.points.lock().unwrap();
        for point in points.iter() {
            point.initialize();
        }
        points.clear();
    }

    // RUDRA-GLUE: num_points (no Ghidra counterpart found)
    /// Number of registered extension points.
    pub fn num_points(&self) -> usize {
        self.points.lock().unwrap().len()
    }

    // RUDRA-GLUE: is_empty (no Ghidra counterpart found)
    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.points.lock().unwrap().is_empty()
    }
}

/// The global singleton registry, accessible from anywhere. This replaces
/// Ghidra's static `getList()` singleton.
static GLOBAL_REGISTRY: once_cell_shim::OnceCell<CapabilityRegistry> =
    once_cell_shim::OnceCell::new();

/// Lightweight once_cell shim to avoid adding a dependency.
mod once_cell_shim {
    use std::sync::OnceLock;
    pub type OnceCell<T> = OnceLock<T>;
}

// RUDRA-GLUE: global_registry (no Ghidra counterpart found)
/// Get the global capability registry, initializing it on first access.
pub fn global_registry() -> &'static CapabilityRegistry {
    GLOBAL_REGISTRY.get_or_init(|| CapabilityRegistry::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestCapability {
        initialized: Arc<AtomicBool>,
    }

    impl CapabilityPoint for TestCapability {
        fn initialize(&self) {
            self.initialized.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_registry_empty() {
        let reg = CapabilityRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.num_points(), 0);
    }

    #[test]
    fn test_register_and_initialize() {
        let reg = CapabilityRegistry::new();
        let initialized = Arc::new(AtomicBool::new(false));
        let cap = Arc::new(TestCapability {
            initialized: initialized.clone(),
        });
        reg.register(cap);
        assert_eq!(reg.num_points(), 1);
        assert!(!initialized.load(Ordering::SeqCst));

        reg.initialize_all();
        assert!(initialized.load(Ordering::SeqCst));
        // List is cleared after initialization.
        assert_eq!(reg.num_points(), 0);
    }

    #[test]
    fn test_multiple_capabilities() {
        let reg = CapabilityRegistry::new();
        let init1 = Arc::new(AtomicBool::new(false));
        let init2 = Arc::new(AtomicBool::new(false));
        reg.register(Arc::new(TestCapability {
            initialized: init1.clone(),
        }));
        reg.register(Arc::new(TestCapability {
            initialized: init2.clone(),
        }));
        assert_eq!(reg.num_points(), 2);
        reg.initialize_all();
        assert!(init1.load(Ordering::SeqCst));
        assert!(init2.load(Ordering::SeqCst));
    }

    #[test]
    fn test_global_registry() {
        let reg1 = global_registry();
        let reg2 = global_registry();
        // Same singleton.
        assert!(std::ptr::eq(reg1, reg2));
    }
}

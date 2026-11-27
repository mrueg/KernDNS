//! A Corefile that fails to load must leave the running configuration's
//! global plugin state alone: readiness checks (`ready`) and the `reload`
//! interval are registered during setup, so a setup error part way used to
//! leave them cleared or half replaced after a failed reload. Its own test
//! binary, as that state is process-wide.

use std::time::Duration;

use kerndns_core::{readiness, reload};
use kerndns_server::{Options, load};

#[test]
fn failed_load_keeps_readiness_and_reload_interval() {
    let registry = kerndns_plugins::registry();
    let opts = Options::default();
    load(".:0 {\n reload 3s 0s\n whoami\n}\n", "Corefile", &registry, &opts).unwrap();
    assert_eq!(reload::interval(), Some(Duration::from_secs(3)));
    assert_eq!(readiness::ready(), (true, vec![]));

    // erratic registers a (not yet ready) check, then whoami's setup fails
    let bad = ".:0 {\n erratic\n whoami extra\n}\n";
    assert!(load(bad, "Corefile", &registry, &opts).is_err());
    assert_eq!(readiness::ready(), (true, vec![]), "readiness of the running config");
    assert_eq!(
        reload::interval(),
        Some(Duration::from_secs(3)),
        "reload of the running config"
    );

    // a good load still replaces both
    load(".:0 {\n erratic\n}\n", "Corefile", &registry, &opts).unwrap();
    assert_eq!(readiness::ready(), (false, vec!["erratic".to_string()]));
    assert_eq!(reload::interval(), None);
}

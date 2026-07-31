//! Regression for the consensus crypto-verification production gate.
//!
//! Integration tests link `poker_l1` as a normal dependency, so `cfg(test)` is
//! not set inside the library. State-carried development flags must therefore
//! be unable to disable any Mental Poker verifier in this build mode.

use poker_l1::vm::contracts::texas_poker::types::TableConfig;

#[test]
fn state_carried_crypto_skip_flags_are_ignored_outside_crate_unit_tests() {
    let config = TableConfig::default();

    assert!(
        config.zk_skip_enabled,
        "legacy serialized flag remains present"
    );
    assert!(config.zk_skip_shuffle);
    assert!(config.zk_skip_reveal);
    assert!(config.zk_skip_reconstruct);
    assert!(config.zk_skip_remask);

    assert!(!config.skip_shuffle());
    assert!(!config.skip_reveal());
    assert!(!config.skip_reconstruct());
    assert!(!config.skip_remask());
}

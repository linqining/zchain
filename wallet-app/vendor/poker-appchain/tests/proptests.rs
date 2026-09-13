//! M1-ACC-1 属性测试：任意插入/消费序列下包含证明正确、nullifier 全局唯一。
//!
//! B5 追加：任意操作序列（deposit/buyin/settle/transfer/withdraw/投毒
//! 双花）下 `LedgerState.owner_index` 与全量扫描逐位一致（含消费后移除、
//! REAL/PLAY 分开统计、空集合即删键）。

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

use poker_appchain::fee::FeePolicy;
use poker_appchain::felt::{felt_from_u64, felt_to_bytes32};
use poker_appchain::keys::spend_digest;
use poker_appchain::merkle::PoseidonMerkleTree;
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::{AssetClass, Note, NoteSpec};
use poker_appchain::nullifier_set::NullifierSet;
use poker_appchain::ops::{scope, Operation};
use poker_appchain::sequencer::{LedgerState, NoteEntry, Sequencer, SequencerConfig};
use poker_appchain::settlement::{
    flat_settlement_plan, RakeSplitRecord, SettleInput, SettlementRecord, SpendAuth,
};

use common::TestUser;

/// u64 序号 → 32 字节幂等键（高位补零，测试内计数器唯一）。
fn id32(v: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&v.to_be_bytes());
    b
}

/// 属性测试体内断言索引一致性（proptest 宏体不携带 Result 返回，失败即 panic，
/// proptest 会捕获并按失败收缩）。
fn assert_index_ok(state: &LedgerState) {
    if let Err(e) = assert_index_matches_scan(state) {
        panic!("owner index invariant violated: {e}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn merkle_proofs_survive_any_append_order(insertions in proptest::collection::vec(any::<u64>(), 1..80)) {
        let mut tree = PoseidonMerkleTree::new();
        let mut idxs = Vec::with_capacity(insertions.len());
        for (i, v) in insertions.iter().enumerate() {
            let idx = tree.append(felt_from_u64((*v).wrapping_add(i as u64 | 1))).unwrap();
            idxs.push(idx);
        }
        let root = tree.root();
        for (i, idx) in idxs.iter().enumerate() {
            let p = tree.proof(*idx).unwrap();
            prop_assert!(
                PoseidonMerkleTree::verify_proof(
                    felt_from_u64((insertions[i]).wrapping_add(i as u64 | 1)),
                    &p,
                    root
                ),
                "leaf {i} proof must verify against final root"
            );
        }
    }

    #[test]
    fn nullifier_set_rejects_any_duplicate(values in proptest::collection::vec(any::<u64>(), 1..60)) {
        let mut set = NullifierSet::new();
        let mut seen = std::collections::HashSet::new();
        for v in values {
            let f = felt_from_u64(v);
            if seen.insert(v) {
                set.insert(f).unwrap();
                prop_assert!(set.contains(&f));
            } else {
                prop_assert!(matches!(
                    set.insert(f),
                    Err(poker_appchain::AppchainError::DoubleSpend)
                ));
            }
        }
    }

    /// B5 核心属性：任意操作序列下 owner_index 与全量扫描一致。
    ///
    /// 覆盖路径：deposit 铸入、buy-in（消费 balance note + 铸 seat note）、
    /// settle（消费 2 seat + 铸 payout）、transfer（消费 + 铸输出）、
    /// withdraw（销毁）、投毒 transfer（同 nullifier 双花 → 消费段部分
    /// 失败，索引仍须与 notes 精确同步）。每次操作后（无论成败）断言：
    /// ① 索引 == 全量扫描（精确相等，空集删键）；② REAL/PLAY 余额聚合
    /// 等价；③ notes_of / note_entries_of 的承诺集 == 扫描集。
    #[test]
    fn owner_index_matches_full_scan(
        steps in proptest::collection::vec((any::<u8>(), any::<u8>(), any::<u8>(), any::<u64>()), 1..48),
    ) {
        let users: Vec<TestUser> = (1..=3u8).map(TestUser::new).collect();
        let pks: Vec<[u8; 33]> = users.iter().map(|u| u.pk()).collect();
        let mut seq = Sequencer::new(
            poker_appchain::keys::SequencerKey::from_seed(&[97u8; 32]),
            SequencerConfig {
                ops_per_min: u32::MAX,
                open_table_per_min: u32::MAX,
                // 属性测试聚焦索引一致性；证明水位与索引无关（纯性能结构）
                admission_proven_only: false,
                ..SequencerConfig::default()
            },
            Arc::new(MetricsRegistry::new()),
        );
        let mut deposit_seq = 0u64;
        let mut table_seq = 0u64;
        let mut request_seq = 0u64;
        let mut binding_seq = 0u64;
        let mut open_tables: Vec<u64> = Vec::new();

        for (i, &(k, a, b, d)) in steps.iter().enumerate() {
            let ts = 1_000u64 + i as u64 * 100;
            let owner = users[(a % 3) as usize].clone();
            let other = users[(b % 3) as usize].clone();
            let amount = 100 + (d % 900);
            let op: Option<Operation> = match k % 7 {
                0 => {
                    deposit_seq += 1;
                    Some(Operation::Deposit {
                        deposit_id: id32(deposit_seq),
                        owner: owner.pk(),
                        asset_class: if d & 1 == 0 { AssetClass::Real } else { AssetClass::Play },
                        amount,
                    })
                }
                1 => {
                    table_seq += 1;
                    let table = table_seq;
                    open_tables.push(table);
                    Some(Operation::OpenTable { table_id: table, policy: FeePolicy::Zero })
                }
                2 => {
                    // buy-in：owner 的 balance note → 本桌 seat note
                    let note = oracle_balance_note(seq.state(), &owner.pk(), d);
                    let table = pick_table(&open_tables, d);
                    match (note, table) {
                        (Some(note), Some(table)) => {
                            let effect = Operation::BuyIn {
                                table_id: table,
                                spends: vec![],
                                notes: vec![],
                                seat_owner: owner.pk(),
                            }
                            .effect_digest();
                            Some(Operation::BuyIn {
                                table_id: table,
                                spends: vec![owner.auth(&note, scope::BUYIN, &effect)],
                                notes: vec![note],
                                seat_owner: owner.pk(),
                            })
                        }
                        _ => None,
                    }
                }
                3 => {
                    // transfer：owner → other 拆分转账（守恒）
                    let note = oracle_balance_note(seq.state(), &owner.pk(), d);
                    match note {
                        Some(note) if note.amount >= 2 => {
                            let amt = note.amount;
                            let s = 1 + (d >> 8) % (amt - 1);
                            let class = note.asset_class;
                            let mk = |who: [u8; 33], v: u64| NoteSpec {
                                asset_class: class,
                                amount: v,
                                owner: who,
                                table_id: None,
                                pot_index: 0,
                                runout_index: 0,
                            };
                            let outputs = vec![mk(other.pk(), s), mk(owner.pk(), amt - s)];
                            let effect = Operation::Transfer {
                                spends: vec![],
                                notes: vec![],
                                outputs: outputs.clone(),
                            }
                            .effect_digest();
                            Some(Operation::Transfer {
                                spends: vec![owner.auth(&note, scope::TRANSFER, &effect)],
                                notes: vec![note],
                                outputs,
                            })
                        }
                        Some(note) => {
                            // 面额 1：整笔转给 other
                            let outputs = vec![NoteSpec {
                                asset_class: note.asset_class,
                                amount: 1,
                                owner: other.pk(),
                                table_id: None,
                                pot_index: 0,
                                runout_index: 0,
                            }];
                            let effect = Operation::Transfer {
                                spends: vec![],
                                notes: vec![],
                                outputs: outputs.clone(),
                            }
                            .effect_digest();
                            Some(Operation::Transfer {
                                spends: vec![owner.auth(&note, scope::TRANSFER, &effect)],
                                notes: vec![note],
                                outputs,
                            })
                        }
                        None => None,
                    }
                }
                4 => {
                    // withdraw：销毁 owner 的 balance note（consume 路径）
                    let note = oracle_balance_note(seq.state(), &owner.pk(), d);
                    note.map(|note| {
                        request_seq += 1;
                        let request_id = id32(request_seq);
                        let effect = Operation::WithdrawRequest {
                            spend: SpendAuth {
                                commitment: [0; 32],
                                nullifier: [0; 32],
                                sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                            },
                            note: note.clone(),
                            request_id,
                        }
                        .effect_digest();
                        Operation::WithdrawRequest {
                            spend: owner.auth(&note, scope::WITHDRAW, &effect),
                            note,
                            request_id,
                        }
                    })
                }
                5 => {
                    // settle：本桌 2 张 seat note → 守恒 payout（零费）
                    let seats = match pick_table(&open_tables, d) {
                        Some(t) => oracle_seat_notes(seq.state(), t),
                        None => Vec::new(),
                    };
                    // 取两张不同 owner 的 seat note
                    let mut pair: Option<(Note, Note)> = None;
                    for x in &seats {
                        for y in &seats {
                            if x.owner != y.owner {
                                pair = Some((x.clone(), y.clone()));
                                break;
                            }
                        }
                        if pair.is_some() {
                            break;
                        }
                    }
                    match pair {
                        Some((sa, sb)) => {
                            binding_seq += 1;
                            let table_id = sa.table_id.expect("seat note has table");
                            let pot = u64::from(sa.amount) + u64::from(sb.amount);
                            let mut awards = [0u64; 9];
                            awards[0] = sa.amount;
                            awards[1] = sb.amount;
                            let plan = flat_settlement_plan(pot, 0b11, awards);
                            let mk = |who: [u8; 33], v: u64| NoteSpec {
                                asset_class: sa.asset_class,
                                amount: v,
                                owner: who,
                                table_id: None,
                                pot_index: 0,
                                runout_index: 0,
                            };
                            let mut record = SettlementRecord {
                                table_id,
                                hand_binding: id32(binding_seq),
                                policy_commitment: FeePolicy::Zero.commitment_bytes(),
                                pot,
                                inputs: vec![
                                    SettleInput {
                                        note: sa.clone(),
                                        spend: SpendAuth {
                                            commitment: [0; 32],
                                            nullifier: [0; 32],
                                            sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                                        },
                                    },
                                    SettleInput {
                                        note: sb.clone(),
                                        spend: SpendAuth {
                                            commitment: [0; 32],
                                            nullifier: [0; 32],
                                            sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                                        },
                                    },
                                ],
                                payouts: vec![mk(sa.owner, sa.amount), mk(sb.owner, sb.amount)],
                                rake: RakeSplitRecord {
                                    total: 0,
                                    treasury_out: None,
                                    operator_out: None,
                                },
                                plan,
                                hand_proof: None,
                            };
                            let ua = users.iter().find(|u| u.pk() == sa.owner).expect("seat owner");
                            let ub = users.iter().find(|u| u.pk() == sb.owner).expect("seat owner");
                            record.inputs[0].spend = ua.settle_auth(&sa, &record);
                            record.inputs[1].spend = ub.settle_auth(&sb, &record);
                            Some(Operation::Settle(Box::new(record)))
                        }
                        None => None,
                    }
                }
                _ => {
                    // 投毒 transfer：同一 nullifier 签两笔 spend → 第二笔在
                    // nullifier 步失败（前一张 note 已从 notes/索引移除，状态
                    // 部分变更）——索引必须与全量扫描保持一致
                    let class = if d & 1 == 0 { AssetClass::Real } else { AssetClass::Play };
                    let notes = oracle_two_same_class(seq.state(), &owner.pk(), class);
                    match notes {
                        Some((n1, n2)) => {
                            let amt = u64::from(n1.amount).saturating_add(u64::from(n2.amount));
                            let nf1 = felt_to_bytes32(&n1.nullifier(&owner.secret));
                            let outputs = vec![NoteSpec {
                                asset_class: class,
                                amount: amt,
                                owner: owner.pk(),
                                table_id: None,
                                pot_index: 0,
                                runout_index: 0,
                            }];
                            let effect = Operation::Transfer {
                                spends: vec![],
                                notes: vec![],
                                outputs: outputs.clone(),
                            }
                            .effect_digest();
                            let d1 = spend_digest(&n1.commitment_bytes(), &nf1, scope::TRANSFER, &effect);
                            let d2 = spend_digest(&n2.commitment_bytes(), &nf1, scope::TRANSFER, &effect);
                            Some(Operation::Transfer {
                                spends: vec![
                                    SpendAuth {
                                        commitment: n1.commitment_bytes(),
                                        nullifier: nf1,
                                        sig: owner.key.sign(&d1),
                                    },
                                    SpendAuth {
                                        commitment: n2.commitment_bytes(),
                                        nullifier: nf1,
                                        sig: owner.key.sign(&d2),
                                    },
                                ],
                                notes: vec![n1, n2],
                                outputs,
                            })
                        }
                        None => None,
                    }
                }
            };
            if let Some(op) = op {
                // 成败皆可：失败路径（含消费段部分失败）同样不得让索引漂移
                let _ = seq.submit(op, ts);
            }
            // 无论成败：索引与全量扫描精确一致
            assert_index_ok(seq.state());
        }
        // 终态再断言一次（REAL/PLAY 分开统计等价在 helper 内逐 owner 核对）
        assert_index_ok(seq.state());
        for pk in &pks {
            prop_assert_eq!(seq.state().balances_of(pk), scan_balances(seq.state(), pk));
        }
    }
}

/// 随机挑一张 owner 名下 table_id 为 None 的 note（独立全量扫描 oracle，
/// 刻意不走被测索引）。
fn oracle_balance_note(state: &LedgerState, owner: &[u8; 33], seed: u64) -> Option<Note> {
    let mut cands: Vec<Note> = state
        .notes
        .values()
        .filter(|e| e.note.owner == *owner && e.note.table_id.is_none())
        .map(|e| e.note.clone())
        .collect();
    cands.sort_by_key(|n| n.commitment_bytes());
    if cands.is_empty() {
        None
    } else {
        Some(cands[(seed % cands.len() as u64) as usize].clone())
    }
}

/// 本桌全部 seat note（oracle 扫描，确定性序）。
fn oracle_seat_notes(state: &LedgerState, table: u64) -> Vec<Note> {
    let mut cands: Vec<Note> = state
        .notes
        .values()
        .filter(|e| e.note.table_id == Some(table))
        .map(|e| e.note.clone())
        .collect();
    cands.sort_by_key(|n| n.commitment_bytes());
    cands
}

/// owner 名下同类两张 balance note（投毒双花用）。
fn oracle_two_same_class(
    state: &LedgerState,
    owner: &[u8; 33],
    class: AssetClass,
) -> Option<(Note, Note)> {
    let mut cands: Vec<Note> = state
        .notes
        .values()
        .filter(|e| {
            e.note.owner == *owner && e.note.table_id.is_none() && e.note.asset_class == class
        })
        .map(|e| e.note.clone())
        .collect();
    cands.sort_by_key(|n| n.commitment_bytes());
    match cands.len() {
        0 | 1 => None,
        _ => Some((cands[0].clone(), cands[1].clone())),
    }
}

fn pick_table(open_tables: &[u64], seed: u64) -> Option<u64> {
    if open_tables.is_empty() {
        None
    } else {
        Some(open_tables[(seed % open_tables.len() as u64) as usize])
    }
}

/// 独立 oracle：对 notes 全量扫描重建 owner → 承诺集映射。
fn scan_owner_index(state: &LedgerState) -> HashMap<[u8; 33], std::collections::HashSet<[u8; 32]>> {
    let mut m: HashMap<[u8; 33], std::collections::HashSet<[u8; 32]>> = HashMap::new();
    for e in state.notes.values() {
        m.entry(e.note.owner).or_default().insert(e.note.commitment_bytes());
    }
    m
}

/// 独立 oracle：全量扫描的 (REAL, PLAY) 聚合。
fn scan_balances(state: &LedgerState, owner: &[u8; 33]) -> (u128, u128) {
    let (mut real, mut play) = (0u128, 0u128);
    for e in state.notes.values() {
        if &e.note.owner == owner {
            match e.note.asset_class {
                AssetClass::Real => real += u128::from(e.note.amount),
                AssetClass::Play => play += u128::from(e.note.amount),
            }
        }
    }
    (real, play)
}

/// 独立 oracle：全量扫描的 owner 承诺集。
fn scan_commitments(state: &LedgerState, owner: &[u8; 33]) -> std::collections::HashSet<[u8; 32]> {
    state
        .notes
        .values()
        .filter(|e| e.note.owner == *owner)
        .map(|e| e.note.commitment_bytes())
        .collect()
}

/// 三重断言：索引 == 扫描（精确，含空集删键）、余额聚合等价、notes_of 等。
fn assert_index_matches_scan(state: &LedgerState) -> Result<(), TestCaseError> {
    prop_assert_eq!(state.owner_index.clone(), scan_owner_index(state), "owner_index diverges from full scan");
    // 全部出现过的 owner + 三个测试用户都要核对（防索引键残留/漏删）
    let mut owners: Vec<[u8; 33]> = state.owner_index.keys().copied().collect();
    owners.extend_from_slice(&[
        TestUser::new(1).pk(),
        TestUser::new(2).pk(),
        TestUser::new(3).pk(),
    ]);
    for owner in &owners {
        prop_assert_eq!(
            state.balances_of(owner),
            scan_balances(state, owner),
            "balances_of via index diverges for owner {:?}",
            owner[1..4].to_vec()
        );
        let via_index: std::collections::HashSet<[u8; 32]> =
            state.notes_of(owner).iter().map(|n| n.commitment_bytes()).collect();
        prop_assert_eq!(
            via_index.clone(),
            scan_commitments(state, owner),
            "notes_of diverges for owner {:?}",
            owner[1..4].to_vec()
        );
        let entries: std::collections::HashSet<[u8; 32]> = state
            .note_entries_of(owner)
            .into_iter()
            .map(|e: &NoteEntry| e.note.commitment_bytes())
            .collect();
        prop_assert_eq!(entries, via_index, "note_entries_of vs notes_of diverge");
    }
    Ok(())
}

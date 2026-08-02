//! Native ZCN economic objects.
//!
//! The first production-facing asset model is an immutable owned-coin UTXO:
//! a [`NativeCoin`] object may be created by an authorised system path and may
//! only be spent by deleting the whole object and creating new coin objects.
//! Generic object outputs are not allowed to mint this reserved object type.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Ownership};
use crate::storage::{ObjectBackend, ObjectDb};
use crate::{Address, Hash};

/// Reserved object type for the native ZCN coin.
pub const NATIVE_COIN_OBJECT_TYPE: &str = "0x2::zcn::Coin";

/// One immutable, address-owned native coin output.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct NativeCoin {
    /// Number of indivisible ZCN base units carried by this output.
    pub amount: u64,
}

impl NativeCoin {
    /// Construct a non-zero native coin value.
    pub fn new(amount: u64) -> PokerL1Result<Self> {
        if amount == 0 {
            return Err(PokerL1Error::Other(
                "native coin amount must be greater than zero".into(),
            ));
        }
        Ok(Self { amount })
    }
}

/// Returns true when an object is a reserved native coin output.
#[must_use]
pub fn is_native_coin_object(object: &Object) -> bool {
    object.object_type == NATIVE_COIN_OBJECT_TYPE
}

/// Decode and structurally validate a native coin object.
pub fn decode_native_coin(object: &Object) -> PokerL1Result<NativeCoin> {
    if !is_native_coin_object(object) {
        return Err(PokerL1Error::Other(format!(
            "object {:?} is not a native ZCN coin",
            object.id
        )));
    }
    let coin: NativeCoin = borsh::from_slice(&object.data)
        .map_err(|error| PokerL1Error::Serialization(format!("decode native ZCN coin: {error}")))?;
    NativeCoin::new(coin.amount)
}

/// Create a native coin object for an authorised genesis/treasury/escrow path.
pub fn native_coin_object(
    owner: Address,
    amount: u64,
    creation_nonce: u64,
) -> PokerL1Result<Object> {
    let coin = NativeCoin::new(amount)?;
    let data = borsh::to_vec(&coin)
        .map_err(|error| PokerL1Error::Serialization(format!("encode native ZCN coin: {error}")))?;
    Ok(Object::new(
        ObjectID::new(owner, creation_nonce),
        Ownership::AddressOwned { owner },
        NATIVE_COIN_OBJECT_TYPE,
        data,
        None,
    ))
}

/// Deterministically derive a coin output nonce from the transaction hash and output index.
#[must_use]
pub fn coin_output_nonce(tx_hash: &Hash, output_index: u32) -> u64 {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(b"ZCHAIN_NATIVE_COIN_OUTPUT_V1");
    hasher.update(tx_hash);
    hasher.update(&output_index.to_be_bytes());
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("output length is fixed");
    u64::from_be_bytes(digest[..8].try_into().expect("slice length is fixed"))
}

/// Validated native-coin input selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCoinSelection {
    /// Coin object IDs to consume.
    pub input_ids: Vec<ObjectID>,
    /// Sum of all selected coin amounts.
    pub total: u64,
}

/// One native coin owned by an address, as exposed to wallets and RPC clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedNativeCoin {
    /// Immutable coin object ID used as a transaction input.
    pub id: ObjectID,
    /// Number of indivisible ZCN base units carried by the coin.
    pub amount: u64,
}

/// List all live native coins owned by `owner` in stable object-ID order.
///
/// A reserved coin object with malformed data or a non-zero version is treated as state
/// corruption and returned as an error rather than silently omitted from the wallet balance.
pub fn list_owned_native_coins(
    object_db: &ObjectDb,
    owner: Address,
) -> PokerL1Result<Vec<OwnedNativeCoin>> {
    let mut coins = object_db
        .iter()
        .filter(|object| {
            is_native_coin_object(object) && object.owner == (Ownership::AddressOwned { owner })
        })
        .map(|object| {
            if object.version != 0 {
                return Err(PokerL1Error::Other(format!(
                    "native coin {:?} is mutable/versioned; immutable UTXO version 0 required",
                    object.id
                )));
            }
            Ok(OwnedNativeCoin {
                id: object.id,
                amount: decode_native_coin(object)?.amount,
            })
        })
        .collect::<PokerL1Result<Vec<_>>>()?;
    coins.sort_by_key(|coin| coin.id);
    Ok(coins)
}

/// Aggregate an owner's spendable native-coin balance.
pub fn native_coin_balance(object_db: &ObjectDb, owner: Address) -> PokerL1Result<u64> {
    sum_native_coin_balance(&list_owned_native_coins(object_db, owner)?)
}

/// Aggregate a previously listed set of native coins with overflow protection.
pub fn sum_native_coin_balance(coins: &[OwnedNativeCoin]) -> PokerL1Result<u64> {
    coins.iter().try_fold(0u64, |total, coin| {
        total
            .checked_add(coin.amount)
            .ok_or_else(|| PokerL1Error::Other("native coin balance overflow".into()))
    })
}

/// Select native-coin inputs deterministically while minimizing wallet-visible fragmentation.
///
/// Selection order:
/// 1. exact single-coin match;
/// 2. smallest single coin that covers the amount;
/// 3. largest coins first until covered, minimizing the number of consumed inputs.
///
/// Object ID is the stable tie-breaker. The executor remains authoritative and revalidates the
/// selected IDs when the signed transaction is executed.
pub fn select_native_coins_from_candidates(
    coins: &[OwnedNativeCoin],
    required: u64,
) -> PokerL1Result<NativeCoinSelection> {
    if required == 0 {
        return Err(PokerL1Error::Other(
            "native coin spend amount must be greater than zero".into(),
        ));
    }

    let mut seen = std::collections::BTreeSet::new();
    for coin in coins {
        if coin.amount == 0 {
            return Err(PokerL1Error::Other(format!(
                "native coin {:?} has zero amount",
                coin.id
            )));
        }
        if !seen.insert(coin.id) {
            return Err(PokerL1Error::Other(format!(
                "duplicate native coin candidate {:?}",
                coin.id
            )));
        }
    }

    if let Some(coin) = coins
        .iter()
        .filter(|coin| coin.amount == required)
        .min_by_key(|coin| coin.id)
    {
        return Ok(NativeCoinSelection {
            input_ids: vec![coin.id],
            total: coin.amount,
        });
    }

    if let Some(coin) = coins
        .iter()
        .filter(|coin| coin.amount > required)
        .min_by_key(|coin| (coin.amount, coin.id))
    {
        return Ok(NativeCoinSelection {
            input_ids: vec![coin.id],
            total: coin.amount,
        });
    }

    let available = sum_native_coin_balance(coins)?;
    if available < required {
        return Err(PokerL1Error::InsufficientBalance {
            needed: required,
            has: available,
        });
    }

    let mut sorted = coins.to_vec();
    sorted.sort_by(|left, right| {
        right
            .amount
            .cmp(&left.amount)
            .then_with(|| left.id.cmp(&right.id))
    });

    let mut input_ids = Vec::new();
    let mut total = 0u64;
    for coin in sorted {
        input_ids.push(coin.id);
        total = total
            .checked_add(coin.amount)
            .ok_or_else(|| PokerL1Error::Other("native coin selection sum overflow".into()))?;
        if total >= required {
            break;
        }
    }

    Ok(NativeCoinSelection { input_ids, total })
}

/// List and deterministically select an owner's native coin inputs.
pub fn auto_select_native_coins(
    object_db: &ObjectDb,
    owner: Address,
    required: u64,
) -> PokerL1Result<NativeCoinSelection> {
    select_native_coins_from_candidates(&list_owned_native_coins(object_db, owner)?, required)
}

/// Validate that every declared input is a native coin owned by `owner` and covers `required`.
///
/// Coin objects are immutable UTXOs: the economic path deletes every selected input in full and
/// creates a deterministic change output. Mixing arbitrary objects into a funded Texas call is
/// rejected so the signed input set has one unambiguous monetary interpretation.
pub fn select_owned_native_coins(
    object_db: &dyn ObjectBackend,
    input_ids: &[ObjectID],
    owner: Address,
    required: u64,
) -> PokerL1Result<NativeCoinSelection> {
    if required == 0 {
        return Err(PokerL1Error::Other(
            "native coin spend amount must be greater than zero".into(),
        ));
    }
    if input_ids.is_empty() {
        return Err(PokerL1Error::Other(
            "funded call requires at least one native coin input".into(),
        ));
    }

    let mut total = 0u64;
    let mut seen = std::collections::BTreeSet::new();
    for id in input_ids {
        if !seen.insert(*id) {
            return Err(PokerL1Error::Other(format!(
                "duplicate native coin input {id:?}"
            )));
        }
        let object = object_db.read(id)?;
        if object.owner != (Ownership::AddressOwned { owner }) {
            return Err(PokerL1Error::NotOwner(*id));
        }
        if object.version != 0 {
            return Err(PokerL1Error::Other(format!(
                "native coin input {id:?} is mutable/versioned; immutable UTXO version 0 required"
            )));
        }
        let coin = decode_native_coin(&object)?;
        total = total
            .checked_add(coin.amount)
            .ok_or_else(|| PokerL1Error::Other("native coin input sum overflow".into()))?;
    }
    if total < required {
        return Err(PokerL1Error::InsufficientBalance {
            needed: required,
            has: total,
        });
    }
    Ok(NativeCoinSelection {
        input_ids: input_ids.to_vec(),
        total,
    })
}

/// Consume a validated selection and create deterministic change when necessary.
pub fn consume_native_coin_selection(
    object_db: &mut dyn ObjectBackend,
    selection: &NativeCoinSelection,
    owner: Address,
    required: u64,
    tx_hash: &Hash,
    output_index: u32,
) -> PokerL1Result<Option<ObjectID>> {
    let change = selection.total.checked_sub(required).ok_or_else(|| {
        PokerL1Error::Other("native coin selection is smaller than required amount".into())
    })?;
    let change_object = if change == 0 {
        None
    } else {
        Some(native_coin_object(
            owner,
            change,
            coin_output_nonce(tx_hash, output_index),
        )?)
    };

    if let Some(object) = &change_object {
        if object_db.read(&object.id).is_ok() {
            return Err(PokerL1Error::ObjectIDCollision(object.id));
        }
    }
    for id in &selection.input_ids {
        object_db.delete(id)?;
    }
    if let Some(object) = change_object {
        let id = object.id;
        object_db.create(object)?;
        Ok(Some(id))
    } else {
        Ok(None)
    }
}

/// Create one deterministic escrow payout coin.
pub fn create_native_coin_output(
    object_db: &mut dyn ObjectBackend,
    owner: Address,
    amount: u64,
    tx_hash: &Hash,
    output_index: u32,
) -> PokerL1Result<ObjectID> {
    let object = native_coin_object(owner, amount, coin_output_nonce(tx_hash, output_index))?;
    let id = object.id;
    object_db.create(object)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::object_db::ObjectDb;

    #[test]
    fn owned_coin_selection_consumes_inputs_and_creates_change() {
        let owner = [0x11; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        let first = native_coin_object(owner, 70, 1).unwrap();
        let second = native_coin_object(owner, 50, 2).unwrap();
        db.create(first.clone()).unwrap();
        db.create(second.clone()).unwrap();

        let selected = select_owned_native_coins(&db, &[first.id, second.id], owner, 100).unwrap();
        let change_id =
            consume_native_coin_selection(&mut db, &selected, owner, 100, &[0xAA; 32], 0)
                .unwrap()
                .unwrap();

        assert!(db.read(&first.id).is_err());
        assert!(db.read(&second.id).is_err());
        let change = decode_native_coin(&db.read(&change_id).unwrap()).unwrap();
        assert_eq!(change.amount, 20);
    }

    #[test]
    fn wrong_owner_and_duplicate_inputs_are_rejected_without_mutation() {
        let owner = [0x11; 20];
        let other = [0x22; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        let coin = native_coin_object(owner, 70, 1).unwrap();
        db.create(coin.clone()).unwrap();

        assert!(select_owned_native_coins(&db, &[coin.id], other, 50).is_err());
        assert!(select_owned_native_coins(&db, &[coin.id, coin.id], owner, 50).is_err());
        assert!(db.read(&coin.id).is_ok());
    }

    #[test]
    fn wallet_lists_and_aggregates_only_owned_native_coins() {
        let owner = [0x11; 20];
        let other = [0x22; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        db.create(native_coin_object(owner, 30, 3).unwrap())
            .unwrap();
        db.create(native_coin_object(owner, 70, 1).unwrap())
            .unwrap();
        db.create(native_coin_object(other, 900, 2).unwrap())
            .unwrap();
        db.create(Object::new(
            ObjectID::new(owner, 4),
            Ownership::AddressOwned { owner },
            "0x2::example::NotCoin",
            vec![],
            None,
        ))
        .unwrap();

        let coins = list_owned_native_coins(&db, owner).unwrap();
        assert_eq!(coins.len(), 2);
        assert_eq!(coins[0].id.creation_nonce, 1);
        assert_eq!(coins[1].id.creation_nonce, 3);
        assert_eq!(native_coin_balance(&db, owner).unwrap(), 100);
    }

    #[test]
    fn auto_selection_prefers_exact_then_smallest_covering_coin() {
        let owner = [0x11; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        let exact = native_coin_object(owner, 50, 3).unwrap();
        let smallest_cover = native_coin_object(owner, 60, 2).unwrap();
        let large = native_coin_object(owner, 100, 1).unwrap();
        for coin in [&large, &smallest_cover, &exact] {
            db.create(coin.clone()).unwrap();
        }

        let selected = auto_select_native_coins(&db, owner, 50).unwrap();
        assert_eq!(selected.input_ids, vec![exact.id]);
        assert_eq!(selected.total, 50);

        let selected = auto_select_native_coins(&db, owner, 55).unwrap();
        assert_eq!(selected.input_ids, vec![smallest_cover.id]);
        assert_eq!(selected.total, 60);
    }

    #[test]
    fn auto_selection_uses_largest_first_with_stable_ties() {
        let owner = [0x11; 20];
        let coins = vec![
            OwnedNativeCoin {
                id: ObjectID::new(owner, 3),
                amount: 40,
            },
            OwnedNativeCoin {
                id: ObjectID::new(owner, 1),
                amount: 40,
            },
            OwnedNativeCoin {
                id: ObjectID::new(owner, 2),
                amount: 30,
            },
        ];

        let selected = select_native_coins_from_candidates(&coins, 70).unwrap();
        assert_eq!(
            selected.input_ids,
            vec![ObjectID::new(owner, 1), ObjectID::new(owner, 3)]
        );
        assert_eq!(selected.total, 80);
    }

    #[test]
    fn auto_selection_reports_aggregated_insufficient_balance() {
        let owner = [0x11; 20];
        let mut db = ObjectDb::open_inmemory().unwrap();
        db.create(native_coin_object(owner, 40, 1).unwrap())
            .unwrap();
        db.create(native_coin_object(owner, 30, 2).unwrap())
            .unwrap();

        assert!(matches!(
            auto_select_native_coins(&db, owner, 80),
            Err(PokerL1Error::InsufficientBalance {
                needed: 80,
                has: 70
            })
        ));
    }
}

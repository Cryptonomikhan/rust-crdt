use crate::{merkle_reg::Sha3Hash, Actor, CmRDT, CvRDT, ResetRemove, VClock};
use std::{collections::{BTreeMap, BTreeSet}, fmt::Debug, mem};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey}; 
use alloy_primitives::Address;

type Hash = String;

/// An error that can occur during validation of an update
#[derive(Debug)]
pub enum ValidationError {
    /// A Child is missing
    MissingChild(Hash),
    /// New updates must reference heads
    MissingHead(Hash),
    /// The signature is invalid
    InvalidSignature,
    /// The VClock is not higher than existing VClock
    InvalidVClock,
    /// The Hash provided != the Hash of the Op
    InvalidHash,
    /// We've already seen this update
    AlreadySeen,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ValidationError {}

/// A wrapper around a secp256k1 Signature and it's recovery ID
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecoverableSignature {
    /// The hexidecimal representation of the signature
    pub sig: String,
    /// Single byte recovery ID 
    pub rec: u8
}

/// An operation for a byzantine fault tolerant register
/// where the value converges to a single value.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Op<T, A> 
where 
    A: Ord + AsRef<[u8]> + Actor, 
{
    /// The value that the actor is trying to get the register to converged (or is expected to by all
    /// non-byzantine nodes)
    pub value: T,
    /// The VClock for the Actor that initiated the Op 
    pub vclock: VClock<A>,
    /// The causal history for this update
    pub children: BTreeSet<Hash>,
}

/// An update that wraps the Op plus signature and hash of the op for a BFT Register
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Update<T, A> 
where
    A: Ord + AsRef<[u8]> + Actor,
{
    op: Op<T, A>,
    signature: RecoverableSignature,
    hash: Hash,
}

impl<T: Clone, A> Update<T, A> 
where
    A: Ord + AsRef<[u8]> + Actor,
{
    /// Get the op for this update
    pub fn op(&self) -> Op<T, A> {
        self.op.clone()
    }

    /// Get the recoverable signature for this update
    pub fn signature(&self) -> RecoverableSignature {
        self.signature.clone()
    }

    /// Get the hash of this update
    pub fn hash(&self) -> Hash {
        self.hash.clone()
    }
}

/// Represents a value that can be stored in the register.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node<T, A> 
where
    A: Ord + AsRef<[u8]> + Actor,
{
    op: Update<T, A>,
    value: T
}

impl<T, A: Ord + AsRef<[u8]> + Actor> Node<T, A> {
    /// Creates a new Node
    pub fn new(op: Update<T, A>, value: T) -> Self {
        Self { op, value }
    }
}

impl<T: Clone> Node<T, String> {
    /// Returns t he canonical value for the given node
    pub fn value(&self) -> T {
        self.value.clone()
    }
}

/// The heads of the DAG
#[derive(Debug, Clone)]
pub struct Heads<T, A> 
where A: Ord + AsRef<[u8]> + Actor,
{
    heads: BTreeMap<Hash, Node<T, A>>
}

impl<T, A> Heads<T, A> 
where A: Ord + AsRef<[u8]> + Actor
{

    /// Returns whether the Map is empty or not (no heads)
    pub fn is_empty(&self) -> bool {
        self.heads.is_empty()
    }

    /// Iterate over the content values
    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.heads.values().map(|n| &n.value)
    }

    /// Iterate over the Merkle DAG nodes holding the content values.
    pub fn nodes(&self) -> impl Iterator<Item = &Node<T, A>> {
        self.heads.values()
    }

    /// Iterate over the hashes of the content values.
    pub fn hashes(&self) -> BTreeSet<Hash> {
        self.heads.keys().cloned().collect()
    }

    /// Iterate over the hashes of the content values.
    pub fn hashes_and_nodes(&self) -> impl Iterator<Item = (Hash, &Node<T, A>)> {
        self.heads.iter().map(|(hash, node)| (hash.clone(), node))
    }
}

/// A Single Value register with a history of all updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BFTReg<T, A> 
where
    A: Ord + AsRef<[u8]> + Actor 
{
    heads: BTreeSet<Hash>,
    dag: BTreeMap<Hash, Node<T, A>>,
    orphans: BTreeMap<Hash, Vec<Update<T, A>>>,
    val: Option<Node<T, A>> 
}

impl<T> Default for BFTReg<T, String> {
    fn default() -> Self {
        Self {
            heads: BTreeSet::default(),
            dag: BTreeMap::default(),
            orphans: BTreeMap::default(),
            val: None 
        }
    }
}

impl<T, A: Ord + std::hash::Hash + Clone + AsRef<[u8]>> ResetRemove<A> for BFTReg<T, A> {
    fn reset_remove(&mut self, clock: &VClock<A>) {
        self.dag = mem::take(&mut self.dag)
            .into_iter()
            .filter_map(|(hash, mut node)| {
                node.op.op.vclock.reset_remove(clock);
                if node.op.op.vclock.is_empty() {
                    None // remove this value from the register
                } else {
                    Some((hash, node))
                }
            })
            .collect()
    }
}

impl<T: Clone + Sha3Hash + PartialEq + Debug> CmRDT for BFTReg<T, String> 
{
    type Op = Update<T, String>;
    type Validation = ValidationError;

    fn validate_op(&self, op: &Self::Op) -> Result<(), Self::Validation> {
        log::info!("Attempting to apply op: {:?}", op);
        if self.dag.contains_key(&op.hash) {
            log::info!("Dag contains key, returning invalid");
            return Err(ValidationError::AlreadySeen);
        }
        if self.is_orphaned(&op.hash) {
            return Err(ValidationError::AlreadySeen);
        }
        // Recover and Validate the signature
        let mut hasher = Sha3::v256();
        op.op.hash(&mut hasher);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        if hex::encode(hash) != op.hash {
            return Err(ValidationError::InvalidHash)
        }

        let sig_bytes = hex::decode(op.signature.sig.clone()).map_err(|_| ValidationError::InvalidSignature)?;
        let signature = K256Signature::from_slice(&sig_bytes).map_err(|_| ValidationError::InvalidSignature)?;
        let verifying_key = VerifyingKey::recover_from_msg(
            &hash, &signature, RecoveryId::from_byte(op.signature.rec).ok_or(ValidationError::InvalidSignature)?
        ).map_err(|_| ValidationError::InvalidSignature)?; 
        let address = hex::encode(Address::from_public_key(&verifying_key));

        for child in &op.op.children {
            if !self.dag.contains_key(child) {
                return Err(ValidationError::MissingChild(child.clone()))
            }

            // We can guarantee that child exists, given early exit above
            let child_op = self.dag.get(child).unwrap();
            if child_op.op.op.vclock > op.op.vclock {
                log::error!("Child op vclock strictly greater than op vclock");
                println!("Child op vclock strictly greater than op vclock");
                println!("Child op vclock: {} > op vclock: {}", child_op.op.op.vclock, op.op.vclock);
                return Err(ValidationError::InvalidVClock)
            }
            if child_op.op.op.vclock.get(&address) > op.op.vclock.get(&address) {
                log::error!("Child op actors vclock greater than or equal to op vclock");
                log::error!("Child op: {:?}\n\n", child_op);
                log::error!("New op: {:?}", child_op);
                println!("Child op actor vclock: {} > op actor vclock: {}", child_op.op.op.vclock.get(&address), op.op.vclock.get(&address));
                return Err(ValidationError::InvalidVClock)
            }
        }

        if self.val.is_none() {
            return Ok(())
        }

        if self.val.clone().unwrap().op.op.vclock > op.op.vclock {
            return Err(ValidationError::InvalidVClock);
        }

        Ok(()) 
    }

    fn apply(&mut self, op: Self::Op) {
        match &self.validate_op(&op) {
            Ok(()) => {
                let hash = op.hash.clone();
                let node = Node::new(op.clone(), op.op.value.clone());
                self.dag.insert(node.op.hash.clone(), node.clone());
                if self.val.is_none() {
                    println!("self.val is none");
                    self.val = Some(node.clone());
                    self.resolve_orphans(&hash);
                    self.update_heads();
                    return;
                }
                // If the new op contains the current val as a child
                // set new op to current val
                if op.op.children.contains(&self.val.clone().unwrap().op.hash) {
                    println!("new op containers current op as child");
                    self.val = Some(node.clone());
                } else {
                    // Otherwise, check if the op has an explicitly higher vclock
                    if op.op.vclock > self.val.clone().unwrap().op.op.vclock {
                        println!("new has higher vclock than current op");
                        // If so set current val to new op
                        self.val = Some(node.clone());
                    // Otherwise, check if the op's hash is lower than current val hash
                    } else if op.hash < self.val.clone().unwrap().op.hash {
                        println!("new op hash is lower than current op, despite same vclock");
                        // If so, set current val to new op
                        self.val = Some(node.clone());
                        // Move current val into DAG as a head
                    } else {
                        println!("Self.val has equal or higher vclock and lower hash, leaving as current val and moving new node into dag\n");
                    }
                }

                // Attempt to resolve any orphans
                self.resolve_orphans(&hash);
                self.update_heads();
            }
            Err(ValidationError::MissingChild(e)) => {
                log::error!("Op is missing a child: {}", hex::encode(e));
                self.add_orphan(op);
            }
            Err(e) => {
                log::error!("Op rejected: {e}");
                println!("Error applying op: {e}");
            }
        }
    }
}

impl<T: Clone + PartialEq + Sha3Hash + Debug> CvRDT for BFTReg<T, String> {
    type Validation = std::io::Error;
    fn validate_merge(&self, _other: &Self) -> Result<(), Self::Validation> {
        Ok(())
    }

    fn merge(&mut self, mut other: Self) {
        let other_dag = std::mem::take(&mut other.dag); 
        for (hash, node) in other_dag {
            if !self.dag.contains_key(&hash) {
                if self.validate_op(&node.op).is_ok() {
                    self.dag.insert(hash, node);
                }
            }
        }

        let other_orphans = std::mem::take(&mut other.orphans);
        for (missing_hash, orphan_ops) in other_orphans {
            let entry = self.orphans.entry(missing_hash).or_insert_with(Vec::new);
            entry.extend(orphan_ops.into_iter());
        }

        self.resolve_all_orphans();
        self.recalculate_current_value();
    }
}

impl<T: Clone + Sha3Hash + PartialEq + Debug> BFTReg<T, String> {
    /// Returns the current cannonical value
    pub fn val(&self) -> Option<Node<T, String>> {
        self.val.clone()
    }

    /// Checks if the dag contains the hash of an update
    pub fn dag_contains(&self, key: &Hash) -> bool {
        self.dag.contains_key(key)
    }

    /// Checks if the update was orphaned
    pub fn is_orphaned(&self, key: &Hash) -> bool {
        self.orphans.iter().any(|(_, v)| v.iter().any(|op| op.hash == *key))
    }

    /// CHecks if the update was accepted as a head
    pub fn is_head(&self, key: &Hash) -> bool {
        self.heads.contains(key)
    }

    /// Checks if the updates value is the current cannonical value of the register
    pub fn is_val(&self, val: &T) -> bool {
        if let Some(v) = self.val() {
            println!("{:?} == {:?}", v.value(), val);
            v.value() == *val 
        } else { false }
    }

    /// Creates an update with the proper context
    pub fn update(&self, value: T, actor: String, pk: SigningKey) -> Result<Update<T, String>, Box<dyn std::error::Error>> {
        let mut children: BTreeSet<Hash> = BTreeSet::new();
        let vclock = if let Some(val) = &self.val {
            log::info!("Value is Some");
            children.insert(val.op.hash.clone());
            children.extend(self.get_heads());
            log::info!("Added heads and current value to children");
            let mut vclock = val.op.op.vclock.clone();
            log::info!("Acquired VClock... CURRENT VCLOCK: {vclock:?}");
            let dot = vclock.inc(actor.clone());
            log::info!("Incremented VClock, applying dot {dot:?}...");
            vclock.apply(dot);
            log::info!("Applied dot to vclock: NEW VCLOCK {vclock:?}...");
            vclock
        } else {
            log::info!("Val is none, creating new vclock");
            println!("Val is none, creating new vclock");
            let mut vclock = VClock::new();
            let dot = vclock.inc(actor.clone());
            vclock.apply(dot);
            vclock
        };

        log::info!("\n\nVCLOCK: {vclock:?}");
        println!("\n\nVCLOCK: {vclock:?}");

        let op = Op {
            value,
            vclock,
            children
        };

        log::info!("Built op, hashing and signing");
        println!("Built op, hashing and signing");

        let mut hasher = Sha3::v256();
        op.hash(&mut hasher);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        let (sig, rec) = pk.sign_prehash_recoverable(&hash)?;
        let signature = RecoverableSignature {
            sig: hex::encode(sig.to_vec()),
            rec: rec.to_byte()
        };

        let hash = hex::encode(hash);

        log::info!("Hashed and signed op, returning update update: {hash}");
        println!("Hashed and signed op, returning update update: {hash}");
        Ok(Update {
            op,
            signature,
            hash
        })
    }

    /// Returns the heads (concurrent values) of the DAG, including 
    /// the current cannonical value
    pub fn read(&self) -> Heads<T, String> {
        let mut map = BTreeMap::new();
        if let Some(val) = &self.val {
            map.insert(val.op.hash.clone(), val.clone());
        }
        map.extend(
            self.heads.iter().filter_map(|hash| {
                match self.dag.get(hash) {
                    Some(node) => Some((hash.clone(), node.clone())),
                    None => None
                }
            })
        );

        Heads { heads: map }
    }

    fn resolve_orphan(&mut self, orphan: &Update<T, String>) -> bool {
        let progress = self.validate_op(orphan).is_ok();
        self.apply(orphan.clone());
        progress
    }

    fn resolve_orphans(&mut self, hash: &String) -> bool {
        println!("Attempting to resolve orphans for {hash}");
        println!("Orphans: {:?}", self.orphans);
        let mut progress = false;
        if let Some(orphan_ops) = self.orphans.remove(&hash.clone()) {
            println!("Found orphans dependent on {hash}");
            progress = orphan_ops.iter().any(|v| self.resolve_orphan(v));
        }
        progress
    }

    fn resolve_all_orphans(&mut self) {
        let mut resolved = BTreeSet::new();
        loop {
            let mut progress = false;

            let orphans = self.orphans.clone();
            for missing_hash in orphans.keys() {
                if self.dag.contains_key(missing_hash) {
                    progress = self.resolve_orphans(missing_hash);
                }

                resolved.insert(missing_hash.clone());
            }

            self.orphans.retain(|h, _| !resolved.contains(h));

            if !progress {
                break
            }
        }
    }

    fn recalculate_current_value(&mut self) {
        let mut best_val = self.val().clone();

        for node in self.dag.values() {
            if let Some(ref mut current_val) = best_val {
                if node.op.op.vclock > current_val.op.op.vclock {
                    *current_val = node.clone();
                } else if node.op.op.vclock == current_val.op.op.vclock {
                    if node.op.hash < current_val.op.hash {
                        *current_val = node.clone();
                    }
                }
            } else {
                best_val = Some(node.clone());
            }
        }

        self.val = best_val; 
    }

    fn add_orphan(&mut self, op: Update<T, String>) {
        for child in &op.op.children {
            if !self.dag.contains_key(child) {
                self.orphans.entry(child.clone())
                    .or_insert_with(Vec::new)
                    .push(op.clone());
            }     
        }
    }

    fn get_heads(&self) -> Vec<Hash> {
        let referenced_children: BTreeSet<Hash> = self.dag.values().flat_map(|op| op.op.op.children.iter().cloned()).collect();
        let heads: Vec<Hash> = self.dag.keys().filter(|hash| !referenced_children.contains(*hash))
            .cloned().collect();
        heads
    }

    fn update_heads(&mut self) {
        self.heads = self.get_heads().iter().cloned().collect();
        if let Some(val) = &self.val {
            self.heads.insert(val.op.hash.clone());
        }
    }
}

impl<T: Sha3Hash, A: Ord + AsRef<[u8]> + Actor> Sha3Hash for Op<T, A> {
    /// Compute the hash of the operation
    fn hash(&self, hasher: &mut Sha3) {
        self.children.iter().for_each(|child| child.hash(hasher));
        self.value.hash(hasher);
        self.vclock.hash(hasher);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use k256::ecdsa::SigningKey;
    use tiny_keccak::{Hasher, Sha3};

    #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    struct TestValue {
        id: String,
        data: String,
    }

    impl Sha3Hash for TestValue {
        fn hash(&self, hasher: &mut Sha3) {
            hasher.update(self.id.as_bytes());
            hasher.update(self.data.as_bytes());
        }
    }

    #[test]
    fn test_bft_reg_create_initial_update() {
        let actor = "node-1".to_string();
        let pk = SigningKey::random(&mut rand::thread_rng());
        let reg: BFTReg<TestValue, String> = BFTReg::default();

        let value = TestValue {
            id: "value-1".to_string(),
            data: "Initial data".to_string(),
        };

        // Create an initial update
        let update = reg
            .update(value.clone(), actor.clone(), pk.clone())
            .expect("Failed to create initial update");

        // Verify the update structure
        assert_eq!(update.op.value, value);
        assert!(update.op.children.is_empty()); // No children for the first update
    }

    #[test]
    fn test_bft_reg_create_update_with_children() {
        let actor = "node-1".to_string();
        let pk = SigningKey::random(&mut rand::thread_rng());
        let mut reg: BFTReg<TestValue, String> = BFTReg::default();

        let value1 = TestValue {
            id: "value-1".to_string(),
            data: "Initial data".to_string(),
        };

        // Create and apply the first update
        let update1 = reg
            .update(value1.clone(), actor.clone(), pk.clone())
            .expect("Failed to create first update");
        reg.apply(update1.clone());

        let value2 = TestValue {
            id: "value-2".to_string(),
            data: "Updated data".to_string(),
        };

        // Create a second update referencing the first
        let update2 = reg
            .update(value2.clone(), actor.clone(), pk.clone())
            .expect("Failed to create second update");

        // Verify that the second update references the first as a child
        assert!(update2.op.children.contains(&update1.hash));
    }

    #[test]
    fn test_bft_reg_apply_update() {
        let actor = "node-1".to_string();
        let pk = SigningKey::random(&mut rand::thread_rng());
        let mut reg: BFTReg<TestValue, String> = BFTReg::default();

        let value1 = TestValue {
            id: "value-1".to_string(),
            data: "Initial data".to_string(),
        };

        // Create and apply the first update
        let update1 = reg
            .update(value1.clone(), actor.clone(), pk.clone())
            .expect("Failed to create first update");
        reg.apply(update1.clone());

        // Validate the canonical value
        assert!(reg.is_val(&value1));
    }

    #[test]
    fn test_bft_reg_orphan_handling() {
        let actor = "node-1".to_string();
        let pk = SigningKey::random(&mut rand::thread_rng());
        let mut reg: BFTReg<TestValue, String> = BFTReg::default();

        let value1 = TestValue {
            id: "value-1".to_string(),
            data: "Initial data".to_string(),
        };

        // Create the first update but do not apply it
        let update1 = reg
            .update(value1.clone(), actor.clone(), pk.clone())
            .expect("Failed to create first update");

        let value2 = TestValue {
            id: "value-2".to_string(),
            data: "Orphaned data".to_string(),
        };

        // Create a second update referencing the first
        let mut children = BTreeSet::new();
        children.insert(update1.hash.clone());

        let mut vclock = update1.op().vclock.clone();
        let dot = vclock.inc(actor);
        vclock.apply(dot);

        let op = Op {
            value: value2.clone(),
            vclock,
            children,
        };

        let mut hasher = Sha3::v256();
        op.hash(&mut hasher);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        let (sig, rec) = pk.sign_prehash_recoverable(&hash).unwrap();
        let signature = RecoverableSignature {
            sig: hex::encode(sig.to_vec()),
            rec: rec.to_byte(),
        };

        let hash = hex::encode(hash);
        println!("Update 2 hash: {hash}");

        let update2 = Update {
            op,
            signature,
            hash,
        };

        // Apply the orphaned update
        println!("Applying update 2 before update 1");
        reg.apply(update2.clone());

        // Ensure it was stored as an orphan
        assert!(reg.is_orphaned(&update2.hash));
        assert!(reg.orphans.contains_key(&update1.hash.clone()));
        println!("Update 2 is orphaned by update 1");

        // Apply the first update to resolve the orphan
        println!("Applying update 1...");
        reg.apply(update1.clone());

        println!("Update 1 should no longer be orphaned...");
        // Ensure the orphan was resolved
        assert!(!reg.is_orphaned(&update1.hash));
        assert!(reg.is_val(&value2));
    }

    #[test]
    fn test_bft_reg_concurrent_updates() {
        let actor = "node-1".to_string();
        let pk = SigningKey::random(&mut rand::thread_rng());
        let mut reg: BFTReg<TestValue, String> = BFTReg::default();

        let value1 = TestValue {
            id: "value-1".to_string(),
            data: "Initial data".to_string(),
        };

        // Create and apply the first update
        let update1 = reg
            .update(value1.clone(), actor.clone(), pk.clone())
            .expect("Failed to create first update");
        reg.apply(update1.clone());

        let value2 = TestValue {
            id: "value-2".to_string(),
            data: "Concurrent data 1".to_string(),
        };

        let value3 = TestValue {
            id: "value-3".to_string(),
            data: "Concurrent data 2".to_string(),
        };

        // Create two concurrent updates
        let update2 = reg
            .update(value2.clone(), actor.clone(), pk.clone())
            .expect("Failed to create second update");
        let update3 = reg
            .update(value3.clone(), actor.clone(), pk.clone())
            .expect("Failed to create third update");

        // Apply both updates
        reg.apply(update2.clone());
        reg.apply(update3.clone());

        // Ensure both updates are considered heads
        assert!(reg.is_head(&update2.hash));
        assert!(reg.is_head(&update3.hash));
    }
}

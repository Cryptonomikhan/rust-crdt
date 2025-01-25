use crate::{merkle_reg::Sha3Hash, Actor, CmRDT, CvRDT, ResetRemove, VClock};
use std::{collections::{BTreeMap, BTreeSet}, fmt::Debug, mem};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey}; 
use alloy_primitives::Address;

type Hash = [u8; 32];

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
    sig: String,
    rec: u8
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
        self.hash
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
        self.heads.keys().copied().collect()
    }

    /// Iterate over the hashes of the content values.
    pub fn hashes_and_nodes(&self) -> impl Iterator<Item = (Hash, &Node<T, A>)> {
        self.heads.iter().map(|(hash, node)| (*hash, node))
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

impl<T: Clone + Sha3Hash + PartialEq> CmRDT for BFTReg<T, String> 
{
    type Op = Update<T, String>;
    type Validation = ValidationError;

    fn validate_op(&self, op: &Self::Op) -> Result<(), Self::Validation> {
        
        if self.dag.contains_key(&op.hash) || self.orphans.contains_key(&op.hash) {
            return Err(ValidationError::AlreadySeen);
        }

        // Recover and Validate the signature
        let mut hasher = Sha3::v256();
        op.op.hash(&mut hasher);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        if hash != op.hash {
            return Err(ValidationError::InvalidHash)
        }

        let sig_bytes = hex::decode(op.signature.sig.clone()).map_err(|_| ValidationError::InvalidSignature)?;
        let signature = K256Signature::from_slice(&sig_bytes).map_err(|_| ValidationError::InvalidSignature)?;
        let verifying_key = VerifyingKey::recover_from_prehash(
            &hash, &signature, RecoveryId::from_byte(op.signature.rec).ok_or(ValidationError::InvalidSignature)?
        ).map_err(|_| ValidationError::InvalidSignature)?; 
        let address = hex::encode(Address::from_public_key(&verifying_key));

        if self.val.is_none() {
            return Ok(())
        }

        for child in &op.op.children {
            if !self.dag.contains_key(child) {
                return Err(ValidationError::MissingChild(*child))
            }

            // We can guarantee that child exists, given early exit above
            let child_op = self.dag.get(child).unwrap();
            if child_op.op.op.vclock > op.op.vclock {
                return Err(ValidationError::InvalidVClock)
            }
            if child_op.op.op.vclock.get(&address) > op.op.vclock.get(&address) {
                return Err(ValidationError::InvalidVClock)
            }
        }

        if self.val.clone().unwrap().op.op.vclock > op.op.vclock {
            return Err(ValidationError::InvalidVClock);
        }

        if let Some(head) = self.get_heads().iter().find(|head| !op.op.children.contains(*head)) {
            return Err(ValidationError::MissingHead(*head));
        }

        Ok(()) 
    }

    fn apply(&mut self, op: Self::Op) {
        match &self.validate_op(&op) {
            Ok(()) => {
                let hash = op.hash;
                let node = Node::new(op.clone(), op.op.value.clone());
                if self.val.is_none() {
                    self.val = Some(node);
                    self.update_heads();
                    return;
                }
                // If the new op contains the current val as a child
                // set new op to current val
                if op.op.children.contains(&self.val.clone().unwrap().op.hash) {
                    self.dag.insert(self.val.clone().unwrap().op.hash, self.val.clone().unwrap().clone());
                    self.val = Some(node.clone());
                } else {
                    // Otherwise, check if the op has an explicitly higher vclock
                    if op.op.vclock > self.val.clone().unwrap().op.op.vclock {
                        // If so set current val to new op
                        self.dag.insert(self.val.clone().unwrap().op.hash, self.val.clone().unwrap());
                        self.val = Some(node.clone());
                    // Otherwise, check if the op's hash is lower than current val hash
                    } else if op.hash < self.val.clone().unwrap().op.hash {
                        self.dag.insert(self.val.clone().unwrap().op.hash, self.val.clone().unwrap());
                        // If so, set current val to new op
                        self.val = Some(node.clone());
                        // Move current val into DAG as a head
                    } else {
                        // Otherwise move the new op into the dag as a head
                        self.dag.insert(op.hash, node.clone());
                    }
                }

                // Attempt to resolve any orphans
                self.resolve_orphans(&hash);
                self.update_heads();
            }
            Err(ValidationError::MissingChild(_)) => {
                self.add_orphan(op);
            }
            Err(_) => {
                //no-op
            }
        }
    }
}

impl<T: Clone + PartialEq + Sha3Hash> CvRDT for BFTReg<T, String> {
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

impl<T: Clone + Sha3Hash + PartialEq> BFTReg<T, String> {
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
        self.orphans.contains_key(key)
    }

    /// CHecks if the update was accepted as a head
    pub fn is_head(&self, key: &Hash) -> bool {
        self.heads.contains(key)
    }

    /// Checks if the updates value is the current cannonical value of the register
    pub fn is_val(&self, val: &T) -> bool {
        if let Some(v) = self.val() {
            v.value() == *val 
        } else { false }
    }

    /// Creates an update with the proper context
    pub fn update(&self, value: T, actor: String, pk: SigningKey) -> Result<Update<T, String>, Box<dyn std::error::Error>> {
        let mut children: BTreeSet<Hash> = BTreeSet::new();
        let vclock = if let Some(val) = &self.val {
            children.insert(val.op.hash);
            children.extend(self.get_heads());
            let mut vclock = val.op.op.vclock.clone();
            let dot = vclock.inc(actor.clone());
            vclock.apply(dot);
            vclock
        } else {
            VClock::new()
        };

        let op = Op {
            value,
            vclock,
            children
        };

        let mut hasher = Sha3::v256();
        op.hash(&mut hasher);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        let (sig, rec) = pk.sign_prehash_recoverable(&hash)?;
        let signature = RecoverableSignature {
            sig: hex::encode(sig.to_vec()),
            rec: rec.to_byte()
        };

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
            map.insert(val.op.hash, val.clone());
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

    fn resolve_orphans(&mut self, hash: &[u8; 32]) -> bool {
        let mut progress = false;
        if let Some(orphan_ops) = self.orphans.remove(hash) {
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

                resolved.insert(*missing_hash);
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
                self.orphans.entry(*child)
                    .or_insert_with(Vec::new)
                    .push(op.clone())
            } 
        }
    }

    fn get_heads(&self) -> Vec<Hash> {
        let referenced_children: BTreeSet<Hash> = self.dag.values().flat_map(|op| op.op.op.children.iter().cloned()).collect();
        self.dag.keys().filter(|hash| !referenced_children.contains(*hash))
            .cloned().collect()
    }

    fn update_heads(&mut self) {
        self.heads = self.get_heads().iter().cloned().collect();
        if let Some(val) = &self.val {
            self.heads.insert(val.op.hash);
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

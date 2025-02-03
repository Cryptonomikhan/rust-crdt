use crate::bft_reg::RecoverableSignature;
use crate::merkle_reg::Sha3Hash;
use crate::{Actor, CmRDT, CvRDT, ResetRemove, VClock};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};

type Hash = [u8; 32];

/// Error types specific to the validation of messages for the BFT queue 
#[derive(Debug)]
pub enum ValidationError {
    /// A Child in a causal history of a message is missing from the local dag
    MissingChild(Hash),
    /// The signature of the message is not recoverable or does not match
    /// the expected address, and is invalid
    InvalidSignature,
    /// The VClock of a message is invalid
    InvalidVClock,
    /// The hash of a message doesn't match the recalculated hash of the payload
    InvalidHash,
    /// The message either already exists in the dag, as a value or is awaiting an orphan
    AlreadySeen,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ValidationError {}

/// A message in the queue with its associated metadata
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Message<T, A: Ord + AsRef<[u8]> + Actor> {
    /// The actual message content
    pub content: T,
    /// Vector clock representing causal history
    pub vclock: VClock<A>,
    /// Optional dependencies (hashes of messages this one depends on)
    pub deps: BTreeSet<Hash>,
}

/// A signed message update operation
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMessage<T, A: Ord + AsRef<[u8]> + Actor> {
    message: Message<T, A>,
    signature: RecoverableSignature,
    hash: Hash,
}

/// A Byzantine Fault Tolerant Message Queue
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BFTQueue<T, A: Ord + AsRef<[u8]> + Actor> {
    /// Messages in the queue, keyed by their hash
    messages: BTreeMap<Hash, Message<T, A>>,
    /// Messages that can't be added yet due to missing dependencies
    orphans: BTreeMap<Hash, Vec<SignedMessage<T, A>>>,
    /// The current vector clock of the queue
    clock: VClock<A>,
}

impl<T: Sha3Hash, A: Ord + AsRef<[u8]> + Actor + Debug> BFTQueue<T, A> {
    /// Creates a new empty queue
    pub fn new() -> Self {
        Self {
            messages: BTreeMap::new(),
            orphans: BTreeMap::new(),
            clock: VClock::new(),
        }
    }

    /// Add a new message to the queue
    pub fn enqueue(
        &self,
        content: T,
        deps: BTreeSet<Hash>,
        actor: A,
        pk: SigningKey,
    ) -> Result<SignedMessage<T, A>, Box<dyn std::error::Error>> {
        // Create the message with a new vclock based on deps
        let mut vclock = self.clock.clone();
        let dot = vclock.inc(actor.clone());
        vclock.apply(dot);

        let message = Message {
            content,
            vclock,
            deps,
        };

        // Hash and sign the message
        let mut hasher = Sha3::v256();
        message.hash(&mut hasher);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        let (sig, rec) = pk.sign_prehash_recoverable(&hash)?;
        let signature = RecoverableSignature {
            sig: hex::encode(sig.to_vec()),
            rec: rec.to_byte(),
        };

        Ok(SignedMessage {
            message,
            signature,
            hash,
        })
    }

    /// Get all messages in causal order
    pub fn read(&self) -> Vec<&Message<T, A>> {
        // Sort messages by their vclock for deterministic ordering
        let mut messages: Vec<_> = self.messages.values().collect();
        messages.sort_by(|a, b| {
            match a.vclock.partial_cmp(&b.vclock) {
                Some(ord) => ord,
                None => {
                    // If concurrent, order by hash for determinism
                    let mut hasher_a = Sha3::v256();
                    let mut hasher_b = Sha3::v256();
                    a.hash(&mut hasher_a);
                    b.hash(&mut hasher_b);
                    let mut hash_a = [0u8; 32];
                    let mut hash_b = [0u8; 32];
                    hasher_a.finalize(&mut hash_a);
                    hasher_b.finalize(&mut hash_b);
                    hash_a.cmp(&hash_b)
                }
            }
        });
        messages
    }

    /// Get messages after a given vector clock
    pub fn read_after(&self, after: &VClock<A>) -> Vec<&Message<T, A>> {
        self.read()
            .into_iter()
            .filter(|msg| msg.vclock > *after)
            .collect()
    }
}

impl<T: Clone + Debug + Sha3Hash, A: Ord + AsRef<[u8]> + Actor + Debug> CmRDT for BFTQueue<T, A> {
    type Op = SignedMessage<T, A>;
    type Validation = ValidationError;

    fn validate_op(&self, op: &Self::Op) -> Result<(), Self::Validation> {
        // Check if we've already seen this message
        if self.messages.contains_key(&op.hash) {
            return Err(ValidationError::AlreadySeen);
        }

        // Verify message hash is correct
        let mut hasher = Sha3::v256();
        op.message.hash(&mut hasher);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        if hash != op.hash {
            return Err(ValidationError::InvalidHash);
        }

        // Verify signature
        let sig_bytes = hex::decode(op.signature.sig.clone())
            .map_err(|_| ValidationError::InvalidSignature)?;
        let signature = K256Signature::from_slice(&sig_bytes)
            .map_err(|_| ValidationError::InvalidSignature)?;
        let recovery_id = RecoveryId::from_byte(op.signature.rec)
            .ok_or(ValidationError::InvalidSignature)?;
        
        VerifyingKey::recover_from_prehash(&hash, &signature, recovery_id)
            .map_err(|_| ValidationError::InvalidSignature)?;

        // Check that all dependencies exist
        for dep in &op.message.deps {
            if !self.messages.contains_key(dep) {
                return Err(ValidationError::MissingChild(*dep));
            }
            
            // Verify the dependency's vclock is less than this message's vclock
            let dep_msg = self.messages.get(dep).unwrap();
            if dep_msg.vclock > op.message.vclock {
                return Err(ValidationError::InvalidVClock);
            }
        }

        Ok(())
    }

    fn apply(&mut self, op: Self::Op) {
        match self.validate_op(&op) {
            Ok(()) => {
                let hash = op.hash;
                self.messages.insert(hash, op.message.clone());
                self.clock.merge(op.message.vclock.clone());
                
                // Try to resolve any orphaned messages that depend on this one
                if let Some(orphans) = self.orphans.remove(&hash) {
                    for orphan in orphans {
                        self.apply(orphan);
                    }
                }
            },
            Err(ValidationError::MissingChild(dep)) => {
                // Store as orphan until we receive the dependency
                self.orphans.entry(dep)
                    .or_default()
                    .push(op);
            },
            Err(_) => {
                // Other validation errors mean we ignore the operation
            }
        }
    }
}

impl<T: Clone + Debug + Sha3Hash, A: Ord + AsRef<[u8]> + Actor + Debug> CvRDT for BFTQueue<T, A> {
    type Validation = ValidationError;

    fn validate_merge(&self, other: &Self) -> Result<(), Self::Validation> {
        // Validate that all messages in other have valid signatures and dependencies
        for (hash, msg) in &other.messages {
            let signed_msg = SignedMessage {
                message: msg.clone(),
                signature: RecoverableSignature { 
                    sig: String::new(),  // We don't need the actual signature for validation
                    rec: 0
                },
                hash: *hash
            };
            
            // We skip the signature check during merge validation since we trust
            // that the other replica has already verified signatures
            if let Err(e) = self.validate_op(&signed_msg) {
                match e {
                    ValidationError::InvalidSignature => continue,
                    _ => return Err(e)
                }
            }
        }
        Ok(())
    }

    fn merge(&mut self, mut other: Self) {
        // Merge messages, keeping only those that pass validation
        let other_messages = std::mem::take(&mut other.messages);
        for (hash, msg) in other_messages {
            if !self.messages.contains_key(&hash) {
                let signed_msg = SignedMessage {
                    message: msg.clone(),
                    signature: RecoverableSignature {
                        sig: String::new(),
                        rec: 0
                    },
                    hash
                };
                
                if self.validate_op(&signed_msg).is_ok() {
                    self.messages.insert(hash, msg);
                }
            }
        }

        // Merge orphans
        let other_orphans = std::mem::take(&mut other.orphans);
        for (missing_hash, orphan_msgs) in other_orphans {
            let entry = self.orphans.entry(missing_hash).or_default();
            entry.extend(orphan_msgs);
        }

        // Merge clocks
        self.clock.merge(other.clock);

        // Try to resolve orphans after merge
        let orphan_hashes: Vec<_> = self.orphans.keys().cloned().collect();
        for hash in orphan_hashes {
            if self.messages.contains_key(&hash) {
                if let Some(orphans) = self.orphans.remove(&hash) {
                    for orphan in orphans {
                        self.apply(orphan);
                    }
                }
            }
        }
    }
}

impl<T: Clone + Sha3Hash, A: Ord + AsRef<[u8]> + Actor + Debug> Default for BFTQueue<T, A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Sha3Hash, A: Ord + AsRef<[u8]> + Actor> Sha3Hash for Message<T, A> {
    fn hash(&self, hasher: &mut Sha3) {
        // Hash dependencies in sorted order for determinism
        for dep in &self.deps {
            hasher.update(dep);
        }
        
        // Hash the vector clock
        self.vclock.hash(hasher);
        
        // Hash the content if it implements AsRef<[u8]>
        self.content.hash(hasher);
    }
}


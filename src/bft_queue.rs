use crate::bft_reg::RecoverableSignature;
use crate::merkle_reg::Sha3Hash;
use crate::{CmRDT, CvRDT, ResetRemove, VClock};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use alloy_primitives::Address;
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
pub struct Message<T: Sha3Hash> {
    /// The actual message content
    pub content: T,
    /// Vector clock representing causal history
    pub vclock: VClock<String>,
    /// Optional dependencies (hashes of messages this one depends on)
    pub deps: BTreeSet<Hash>,
}

/// A signed message update operation
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMessage<T: Sha3Hash> {
    message: Message<T>,
    signature: RecoverableSignature,
    hash: Hash,
}

/// A Byzantine Fault Tolerant Message Queue
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BFTQueue<T: Sha3Hash> {
    /// Messages in the queue, keyed by their hash
    messages: BTreeMap<Hash, Message<T>>,
    /// Messages that can't be added yet due to missing dependencies
    orphans: BTreeMap<Hash, Vec<SignedMessage<T>>>,
    /// The current vector clock of the queue
    clock: VClock<String>,
}

impl<T: Sha3Hash> BFTQueue<T> {
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
        actor: String,
        pk: SigningKey,
    ) -> SignedMessage<T> {
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

        let (sig, rec) = pk.sign_prehash_recoverable(&hash).expect("PANIC: Must be able to sign messages");
        let signature = RecoverableSignature {
            sig: hex::encode(sig.to_vec()),
            rec: rec.to_byte(),
        };

        SignedMessage {
            message,
            signature,
            hash,
        }
    }

    /// Get all messages in causal order
    pub fn read(&self) -> Vec<&Message<T>> {
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
    pub fn read_after(&self, after: &VClock<String>) -> Vec<&Message<T>> {
        self.read()
            .into_iter()
            .filter(|msg| msg.vclock > *after)
            .collect()
    }
}

impl<T: Clone + Debug + Sha3Hash> CmRDT for BFTQueue<T> {
    type Op = SignedMessage<T>;
    type Validation = ValidationError;

    fn validate_op(&self, op: &Self::Op) -> Result<(), Self::Validation> {
        // Check if we've already seen this message
        if self.messages.contains_key(&op.hash) {
            eprintln!("Message has already been seen");
            return Err(ValidationError::AlreadySeen);
        }

        // Verify message hash is correct
        let mut hasher = Sha3::v256();
        op.message.hash(&mut hasher);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        if hash != op.hash {
            eprintln!("Message hash doesn't match calculated hash");
            return Err(ValidationError::InvalidHash);
        }

        // Verify signature
        let sig_bytes = hex::decode(op.signature.sig.clone())
            .map_err(|_| ValidationError::InvalidSignature)?;
        let signature = K256Signature::from_slice(&sig_bytes)
            .map_err(|_| ValidationError::InvalidSignature)?;
        let recovery_id = RecoveryId::from_byte(op.signature.rec)
            .ok_or(ValidationError::InvalidSignature)?;
        
        let address = match VerifyingKey::recover_from_prehash(&hash, &signature, recovery_id) {
            Ok(vk) => {
                hex::encode(Address::from_public_key(&vk))
            }
            Err(e) => {
                eprintln!("Verifying Key unable to be recovered from prehash: {e}");
                return Err(ValidationError::InvalidSignature);
            }
        };

        // Check that all dependencies exist
        for dep in &op.message.deps {
            if !self.messages.contains_key(dep) {
                eprintln!("Local dag is missing a child in the message: {dep:?}");
                return Err(ValidationError::MissingChild(*dep));
            }
            
            // Verify the dependency's vclock is less than this message's vclock
            let dep_msg = self.messages.get(dep).unwrap();
            if dep_msg.vclock > op.message.vclock {
                eprintln!("Dependency Message VClock is strictly greater than operation message VClock, meaning VClock is invalid: {:?} > {:?}", dep_msg.vclock, op.message.vclock);
                return Err(ValidationError::InvalidVClock);
            }

            if dep_msg.vclock.get(&address) >= op.message.vclock.get(&address) {
                eprintln!("Dependency Message Vclock for actor is greater than or equal to op message vclock for actor, which means vclock did not increment for new op: {} >= {}", dep_msg.vclock.get(&address), op.message.vclock.get(&address));
                return Err(ValidationError::InvalidVClock)
            }
        }

        Ok(())
    }

    fn apply(&mut self, op: Self::Op) {
        match self.validate_op(&op) {
            Ok(()) => {
                println!("Op is valid, adding to queue");
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
                eprintln!("Op is missing child, adding to orphans");
                // Store as orphan until we receive the dependency
                self.orphans.entry(dep)
                    .or_default()
                    .push(op);
            },
            Err(e) => {
                eprintln!("Op is invalid: {e}, ignoring");
            }
        }
    }
}

impl<T: Clone + Debug + Sha3Hash>  CvRDT for BFTQueue<T> {
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

impl<T: Clone + Sha3Hash> Default for BFTQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Sha3Hash> Sha3Hash for Message<T> {
    fn hash(&self, hasher: &mut Sha3) {
        // Hash dependencies in sorted order for determinism
        for dep in &self.deps {
            hasher.update(dep);
        }
        
        // Hash the vector clock
        Sha3Hash::hash(&self.vclock, hasher);
        
        // Hash the content if it implements AsRef<[u8]>
        self.content.hash(hasher);
    }
}

impl<T: Clone + Sha3Hash> ResetRemove<String> for BFTQueue<T> {
    fn reset_remove(&mut self, clock: &VClock<String>) {
        // Remove any messages whose vector clocks are dominated by the given clock
        self.messages = std::mem::take(&mut self.messages)
            .into_iter()
            .filter_map(|(hash, mut msg)| {
                msg.vclock.reset_remove(clock);
                if msg.vclock.is_empty() {
                    None // remove this message as all its history is captured in the clock
                } else {
                    Some((hash, msg))
                }
            })
            .collect();

        // Clean up orphans where the missing dependency's clock is dominated
        self.orphans = std::mem::take(&mut self.orphans)
            .into_iter()
            .filter_map(|(hash, orphan_msgs)| {
                if let Some(msg) = self.messages.get(&hash) {
                    if msg.vclock.is_empty() {
                        None // the dependency was reset-removed, so we can drop these orphans
                    } else {
                        Some((hash, orphan_msgs))
                    }
                } else {
                    Some((hash, orphan_msgs)) // keep orphans whose deps we haven't seen
                }
            })
            .collect();

        // Update the queue's clock
        self.clock.reset_remove(clock);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use k256::ecdsa::SigningKey;

    // Test message type that implements necessary traits
    #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    struct TestMessage {
        id: String,
        data: Vec<u8>,
    }

    // Implement AsRef<[u8]> for our test message type
    impl AsRef<[u8]> for TestMessage {
        fn as_ref(&self) -> &[u8] {
            &self.data
        }
    }

    // Helper function to create a test message
    fn create_test_message(id: &str, data: &[u8]) -> TestMessage {
        TestMessage {
            id: id.to_string(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn test_queue_basic_operations() {
        let pk = SigningKey::random(&mut rand::thread_rng());
        let actor = hex::encode(Address::from_private_key(&pk));
        let queue: BFTQueue<TestMessage> = BFTQueue::new();

        // Create and enqueue initial message
        let msg1 = create_test_message("msg1", b"First message");
        let update1 = queue
            .enqueue(msg1.clone(), BTreeSet::new(), actor.clone(), pk.clone());

        // Apply the message and verify it's in the queue
        let mut queue_with_msg = queue.clone();
        queue_with_msg.apply(update1.clone());
        
        let messages = queue_with_msg.read();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content, msg1);
    }

    #[test]
    fn test_queue_message_ordering() {
        let pk1 = SigningKey::random(&mut rand::thread_rng());
        let pk2 = SigningKey::random(&mut rand::thread_rng());
        let actor1 = hex::encode(Address::from_private_key(&pk1));
        let actor2 = hex::encode(Address::from_private_key(&pk2));
        let mut queue: BFTQueue<TestMessage> = BFTQueue::new();

        // First message from actor1
        let msg1 = create_test_message("msg1", b"First message");
        let update1 = queue
            .enqueue(msg1.clone(), BTreeSet::new(), actor1.clone(), pk1);
        
        queue.apply(update1.clone());

        // Second message from actor2 that depends on actor1's message
        let mut deps = BTreeSet::new();
        deps.insert(update1.hash);
        
        let msg2 = create_test_message("msg2", b"Second message");
        let update2 = queue
            .enqueue(msg2.clone(), deps, actor2.clone(), pk2);
        
        queue.apply(update2);

        // Verify messages are in correct order
        let messages = queue.read();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content, msg1);
        assert_eq!(messages[1].content, msg2);

        // We could also verify the vector clocks:
        assert!(messages[1].vclock > messages[0].vclock);
        assert_eq!(messages[0].vclock.get(&actor1), 1);
        assert_eq!(messages[1].vclock.get(&actor2), 1);
    }

    #[test]
    fn test_queue_concurrent_updates() {
        let pk1 = SigningKey::random(&mut rand::thread_rng());
        let pk2 = SigningKey::random(&mut rand::thread_rng());
        let actor1 = hex::encode(Address::from_private_key(&pk1));
        let actor2 = hex::encode(Address::from_private_key(&pk2));
        
        let mut queue1: BFTQueue<TestMessage> = BFTQueue::new();
        let mut queue2 = queue1.clone();

        // Create concurrent messages from different actors
        let msg1 = create_test_message("msg1", b"Message from actor 1");
        let msg2 = create_test_message("msg2", b"Message from actor 2");

        let update1 = queue1
            .enqueue(msg1.clone(), BTreeSet::new(), actor1.clone(), pk1);
        
        let update2 = queue2
            .enqueue(msg2.clone(), BTreeSet::new(), actor2.clone(), pk2);

        // Apply updates to both queues in different orders
        queue1.apply(update1.clone());
        queue1.apply(update2.clone());

        queue2.apply(update2.clone());
        queue2.apply(update1.clone());

        // Verify both queues converged to the same state
        assert_eq!(queue1, queue2);
        
        // Verify both messages are present in both queues
        let messages1: Vec<_> = queue1.read().iter().map(|m| &m.content).collect();
        let messages2: Vec<_> = queue2.read().iter().map(|m| &m.content).collect();
        
        assert!(messages1.contains(&&msg1));
        assert!(messages1.contains(&&msg2));
        assert_eq!(messages1, messages2);
    }

    #[test]
    fn test_queue_dependency_handling() {
        let pk1 = SigningKey::random(&mut rand::thread_rng());
        let pk2 = SigningKey::random(&mut rand::thread_rng());
        let actor1 = hex::encode(Address::from_private_key(&pk1));
        let _actor2 = hex::encode(Address::from_private_key(&pk2));
        
        // Actor 1's queue where they create the messages
        let mut queue1: BFTQueue<TestMessage> = BFTQueue::new();
        
        // Actor 2's queue that will receive messages out of order
        let mut queue2: BFTQueue<TestMessage> = BFTQueue::new();

        // Actor 1 creates and applies first message
        let msg1 = create_test_message("msg1", b"First message");
        let update1 = queue1
            .enqueue(msg1.clone(), BTreeSet::new(), actor1.clone(), pk1.clone());
        queue1.apply(update1.clone());

        // Actor 1 creates second message (with properly incremented vclock)
        let mut deps = BTreeSet::new();
        deps.insert(update1.hash);
        let msg2 = create_test_message("msg2", b"Second message");
        let update2 = queue1
            .enqueue(msg2.clone(), deps, actor1.clone(), pk1.clone());
        queue1.apply(update2.clone());

        // Now Actor 2 receives these messages out of order
        queue2.apply(update2.clone()); // Should be stored as orphan
        assert_eq!(queue2.read().len(), 0);

        queue2.apply(update1.clone()); // Should resolve the orphan
        let messages = queue2.read();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content, msg1);
        assert_eq!(messages[1].content, msg2);
        
        // Verify vclock ordering is correct
        assert!(messages[1].vclock.get(&actor1) > messages[0].vclock.get(&actor1));
    }

    #[test]
    fn test_queue_reset_remove() {
        let pk = SigningKey::random(&mut rand::thread_rng());
        let actor = hex::encode(Address::from_private_key(&pk));
        let mut queue: BFTQueue<TestMessage> = BFTQueue::new();

        // Add a message
        let msg = create_test_message("msg1", b"Test message");
        let update = queue
            .enqueue(msg.clone(), BTreeSet::new(), actor.clone(), pk.clone());

        queue.apply(update);
        assert_eq!(queue.read().len(), 1);

        // Create a clock that dominates the message's clock
        let mut removal_clock = VClock::new();
        removal_clock.apply(removal_clock.inc(actor.clone()));
        removal_clock.apply(removal_clock.inc(actor.clone())); // Increment again to ensure it dominates

        // Apply reset_remove
        queue.reset_remove(&removal_clock);
        assert_eq!(queue.read().len(), 0);
    }

    #[test]
    fn test_queue_invalid_signature() {
        let pk1 = SigningKey::random(&mut rand::thread_rng());
        let pk2 = SigningKey::random(&mut rand::thread_rng()); // Different key
        let actor = hex::encode(Address::from_private_key(&pk1));
        let mut queue: BFTQueue<TestMessage> = BFTQueue::new();

        // Create a valid message
        let msg = create_test_message("msg1", b"Test message");
        let mut update = queue
            .enqueue(msg.clone(), BTreeSet::new(), actor.clone(), pk1);

        // Modify the signature using a different key
        let (_sig, rec) = pk2.sign_prehash_recoverable(&update.hash).unwrap();
        update.signature = RecoverableSignature {
            sig: hex::encode([0u8; 64]),
            rec: rec.to_byte(),
        };

        // Attempt to apply the message with invalid signature
        queue.apply(update);
        assert_eq!(queue.read().len(), 0); // Message should not be accepted
    }
}

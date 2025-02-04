use crate::{map::Op, merkle_reg::{Hash, Sha3Hash}, BFTQueue, CmRDT, CvRDT, Map};
use std::{collections::BTreeSet, fmt::Debug};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};

/// A multi-topic BFT Message Queue
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopicQueue<T: Clone + Debug + Sha3Hash + Default> {
    topics: Map<Hash, BFTQueue<T>, String>
}

impl<T: Clone + Debug + Sha3Hash + Ord + Default> TopicQueue<T> {
    /// Creates a new empty topic queue
    pub fn new() -> Self {
        Self {
            topics: Map::new()
        }
    }

    /// Enqueue a message to a specific topic
    pub fn enqueue(
        &self,
        topic: Hash,
        content: T,
        deps: BTreeSet<Hash>,
        actor: String,
        pk: SigningKey
    ) -> Result<Op<Hash, BFTQueue<T>, String>, Box<dyn std::error::Error>> {
        let add_ctx = self.topics.read_ctx().derive_add_ctx(actor.clone());
        let op = self.topics.update(topic, add_ctx, |q, _ctx| {
            let signed_message = q.enqueue(content, deps, actor, pk);
            signed_message
        });

        Ok(op)
    }

    /// Read messages from a specific topic
    pub fn read_topic(&self, topic: &Hash) -> Option<BFTQueue<T>> {
        self.topics.get(topic).val
    }
}

impl<T: Clone + Debug + Sha3Hash + Ord + Default> CmRDT for TopicQueue<T> {
    type Op = <Map<Hash, BFTQueue<T>, String> as CmRDT>::Op;
    type Validation = <Map<Hash, BFTQueue<T>, String> as CmRDT>::Validation;

    fn validate_op(&self, op: &Self::Op) -> Result<(), Self::Validation> {
        self.topics.validate_op(op)
    }

    fn apply(&mut self, op: Self::Op) {
        self.topics.apply(op)
    }
}

impl<T: Clone + Debug + Sha3Hash + Ord + Default> CvRDT for TopicQueue<T> {
    type Validation = <Map<Hash, BFTQueue<T>, String> as CvRDT>::Validation;

    fn validate_merge(&self, other: &Self) -> Result<(), Self::Validation> {
        self.topics.validate_merge(&other.topics)
    }

    fn merge(&mut self, other: Self) {
        self.topics.merge(other.topics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use tiny_keccak::{Hasher, Sha3};
    use alloy_primitives::Address;

    // Test message type that implements necessary traits
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    struct TestMessage {
        id: String,
        data: Vec<u8>,
    }

    impl AsRef<[u8]> for TestMessage {
        fn as_ref(&self) -> &[u8] {
            &self.data
        }
    }

    impl Default for TestMessage {
        fn default() -> Self {
            Self {
                id: String::new(),
                data: Vec::new(),
            }
        }
    }

    // Helper function to create a test message
    fn create_test_message(id: &str, data: &[u8]) -> TestMessage {
        TestMessage {
            id: id.to_string(),
            data: data.to_vec(),
        }
    }

    // Helper function to create a topic hash
    fn create_topic_hash(name: &str) -> Hash {
        let mut hasher = Sha3::v256();
        hasher.update(name.as_bytes());
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        hash
    }

    #[test]
    fn test_topic_queue_basic_operations() {
        let pk = SigningKey::random(&mut rand::thread_rng());
        let actor = hex::encode(Address::from_private_key(&pk));
        let mut queue = TopicQueue::new();
        
        let topic1 = create_topic_hash("topic1");
        let msg1 = create_test_message("msg1", b"First message");
        
        // Add a message to a topic
        let op = queue.enqueue(
            topic1,
            msg1.clone(),
            BTreeSet::new(),
            actor.clone(),
            pk.clone()
        ).expect("Failed to create enqueue operation");
        
        queue.apply(op);
        
        // Verify the message is in the correct topic
        let topic_queue = queue.read_topic(&topic1).expect("Topic should exist");
        let messages = topic_queue.read();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content, msg1);
    }

    #[test]
    fn test_topic_queue_multiple_topics() {
        let pk = SigningKey::random(&mut rand::thread_rng());
        let actor = hex::encode(Address::from_private_key(&pk));
        let mut queue = TopicQueue::new();
        
        let topic1 = create_topic_hash("topic1");
        let topic2 = create_topic_hash("topic2");
        
        let msg1 = create_test_message("msg1", b"Message for topic 1");
        let msg2 = create_test_message("msg2", b"Message for topic 2");
        
        // Add messages to different topics
        let op1 = queue.enqueue(topic1, msg1.clone(), BTreeSet::new(), actor.clone(), pk.clone())
            .expect("Failed to create first enqueue operation");
        queue.apply(op1);

        let op2 = queue.enqueue(topic2, msg2.clone(), BTreeSet::new(), actor.clone(), pk.clone())
            .expect("Failed to create second enqueue operation");
        queue.apply(op2);
        
        // Verify messages are in correct topics
        let topic1_queue = queue.read_topic(&topic1).expect("Topic 1 should exist");
        let topic2_queue = queue.read_topic(&topic2).expect("Topic 2 should exist");
        
        let messages1 = topic1_queue.read();
        let messages2 = topic2_queue.read();
        
        assert_eq!(messages1.len(), 1);
        assert_eq!(messages2.len(), 1);
        assert_eq!(messages1[0].content, msg1);
        assert_eq!(messages2[0].content, msg2);
    }

    #[test]
    fn test_topic_queue_convergence() {
        let pk1 = SigningKey::random(&mut rand::thread_rng());
        let pk2 = SigningKey::random(&mut rand::thread_rng());
        let actor1 = hex::encode(Address::from_private_key(&pk1));
        let actor2 = hex::encode(Address::from_private_key(&pk2));
        
        let mut queue1 = TopicQueue::new();
        let mut queue2 = TopicQueue::new();
        
        let topic = create_topic_hash("shared_topic");
        
        // Create concurrent messages from different actors
        let msg1 = create_test_message("msg1", b"Message from actor 1");
        let msg2 = create_test_message("msg2", b"Message from actor 2");
        
        let op1 = queue1.enqueue(topic, msg1.clone(), BTreeSet::new(), actor1.clone(), pk1)
            .expect("Failed to create first message");
        let op2 = queue2.enqueue(topic, msg2.clone(), BTreeSet::new(), actor2.clone(), pk2)
            .expect("Failed to create second message");
        
        // Apply operations in different orders
        queue1.apply(op1.clone());
        queue1.apply(op2.clone());
        
        queue2.apply(op2);
        queue2.apply(op1);
        
        // Verify both queues converged to the same state
        assert_eq!(queue1, queue2);

        let topic_1_queue = queue1.read_topic(&topic).expect("Topic should exist in queue1");
        let topic_2_queue = queue2.read_topic(&topic).expect("Topic should exist in queue1");
        
        let topic1_messages = topic_1_queue.read();
        let topic2_messages = topic_2_queue.read();
        
        assert_eq!(topic1_messages.len(), 2);
        assert_eq!(topic2_messages.len(), 2);
        assert_eq!(topic1_messages, topic2_messages);
    }

    #[test]
    fn test_topic_queue_message_dependencies() {
        // Create our signing key and address derived from it
        let pk = SigningKey::random(&mut rand::thread_rng());
        let actor = hex::encode(Address::from_private_key(&pk));
        // Create our queue 
        let mut queue = TopicQueue::new();
        
        // Create topic
        let topic = create_topic_hash("topic");

        // Create Message 1 
        let msg1 = create_test_message("msg1", b"First message");
        
        // Add first message
        let op1 = queue.enqueue(topic, msg1.clone(), BTreeSet::new(), actor.clone(), pk.clone())
            .expect("Failed to create first message");
        // Apply first message 
        queue.apply(op1.clone());
        
        // Get the hash of the first message from the queue
        let topic_queue = queue.read_topic(&topic).expect("Topic should exist");
        let mut hasher = tiny_keccak::Sha3::v256();

        topic_queue.read()[0].hash(&mut hasher);
        let mut first_message_hash = [0u8; 32]; 
        hasher.finalize(&mut first_message_hash); 

        
        // Create second message depending on first
        let mut deps = BTreeSet::new();
        deps.insert(first_message_hash);
        
        // Create second message 
        let msg2 = create_test_message("msg2", b"Dependent message");
        let op2 = queue.enqueue(topic, msg2.clone(), deps, actor, pk)
            .expect("Failed to create dependent message");
        
        // Apply second message 
        queue.apply(op2);
        
        // Verify messages are properly ordered
        let topic_queue = queue.read_topic(&topic).expect("Topic should exist");
        let messages = topic_queue.read();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content, msg1);
        assert_eq!(messages[1].content, msg2);
    }
}

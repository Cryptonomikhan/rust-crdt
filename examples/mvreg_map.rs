extern crate crdts;
extern crate serde;

use serde::{Serialize, Deserialize};
use crdts::{Map, MVReg, CmRDT, CvRDT};

    /// Gets an iterator over the keys of the `Map`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crdts::Map;
    /// use crdts::MVReg;
    /// use crdts::CmRDT;
    ///
    /// type Actor = &'static str;
    /// type Key = &'static str;
    ///
    /// let actor = "actor";
    ///
    /// let mut map: Map<i32, MVReg<Key, Actor>, Actor> = Map::new();
    ///
    /// let add_ctx = map.read_ctx().derive_add_ctx(actor);
    /// map.apply(map.update(100, add_ctx, |v, a| v.write("foo", a)));
    ///
    /// let add_ctx = map.read_ctx().derive_add_ctx(actor);
    /// map.apply(map.update(50, add_ctx, |v, a| v.write("bar", a)));
    ///
    /// let add_ctx = map.read_ctx().derive_add_ctx(actor);
    /// map.apply(map.update(200, add_ctx, |v, a| v.write("baz", a)));
    ///
    ///
    /// let mut keys: Vec<_> = map.keys().map(|key_ctx| *key_ctx.val).collect();
    ///
    /// keys.sort();
    ///
    /// assert_eq!(keys, &[50, 100, 200]);
    /// ```

fn main() {
    type Actor = String;
    type Key = &'static str;
    // Map<ID, MVReg<CustomStruct, Actor>
    let mut mymap: Map<Key, MVReg<Peer, Actor>, Actor> = Map::new(); 

    let peer1 = Peer::default();
    let operator1 = "operator-1".to_string();

    let add_ctx = mymap.read_ctx().derive_add_ctx(operator1);
    let id: &'static str = Box::leak(peer1.id.clone().into_boxed_str());
    let op = mymap.update(id, add_ctx, |reg, ctx| {
        let op = reg.write(peer1, ctx); 
        op
    });

    mymap.apply(op);

    let map_snapshot = mymap.clone();
    let operator2 = "operator-2".to_string();
    let mut theirmap: Map<Key, MVReg<Peer, Actor>, Actor> = Map::new(); 

    let mut peer2 = Peer::default();
    peer2.id = String::from("fghij");
    peer2.ip = "170.28.155.4".to_string();
    peer2.public_key = String::from("0x4def3483a82aabe38d2a8");

    let add_ctx = theirmap.read_ctx().derive_add_ctx(operator2);
    let peer2_id: &'static str = Box::leak(peer2.id.clone().into_boxed_str());
    let op = theirmap.update(peer2_id, add_ctx, |reg, ctx| {
        let op = reg.write(peer2, ctx);
        op
    });

    theirmap.apply(op.clone());
    theirmap.merge(map_snapshot);
    mymap.apply(op);

    println!("{:?}", mymap);
    println!("{:?}", theirmap);

}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Peer {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub cidr_id: i64,
    pub public_key: String,
    pub endpoint: Option<Endpoint>,
    pub keepalive: Option<u16>,
    pub is_admin: bool,
    pub is_disabled: bool,
    pub is_redeemed: bool,
    pub invite_expires: Option<u64>,
    pub candidates: Vec<Endpoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub host: String,
    pub port: u16
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            id: String::from("abcde"),
            name: String::from("test-peer-1"),
            ip: String::from("170.22.150.3"),
            cidr_id: 1,
            public_key: String::from("0x2def3483a82aabe38d2af"),
            endpoint: None, 
            keepalive: None,
            is_admin: true,
            is_disabled: false,
            is_redeemed: true,
            invite_expires: None,
            candidates: Vec::new(), 
        }
    }
}

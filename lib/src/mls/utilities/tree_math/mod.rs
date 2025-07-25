//! Tree Math
//!
//! The tree uses an array-based representation of complete balanced binary
//! trees, as described in [RFC9420 Appendix C](https://www.rfc-editor.org/rfc/rfc9420.html#appendix-C).
//! For example, a tree with 8 leaves:
//! ```text
//!                               X
//!                               |
//!                     .---------+---------.
//!                    /                     \
//!                   X                       X
//!                   |                       |
//!               .---+---.               .---+---.
//!              /         \             /         \
//!             X           X           X           X
//!            / \         / \         / \         / \
//!           /   \       /   \       /   \       /   \
//!          X     X     X     X     X     X     X     X
//!
//!    Node: 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14
//!
//!    Leaf: 0     1     2     3     4     5     6     7
//! ```

#[cfg(test)]
mod tree_math_test;

use serde::{Deserialize, Serialize};

use crate::mls::utilities::error::{Error, Result};

/// `NumLeaves` exposes operations on a tree with a given number of leaves.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NumLeaves(pub(crate) u32);

impl NumLeaves {
    /// Create a `NumLeaves`
    pub fn new(width: u32) -> Self {
        Self(if width == 0 { 0 } else { (width - 1) / 2 + 1 })
    }

    /// Compute the minimum length of the array, ie. the number of nodes.
    pub fn width(&self) -> u32 {
        if self.0 == 0 {
            0
        } else {
            2 * (self.0 - 1) + 1
        }
    }

    /// Return the index of the root node.
    pub fn root(&self) -> NodeIndex {
        NodeIndex((1 << self.width().ilog2()) - 1)
    }

    /// Return the index of the parent node for a non-root node index.
    pub fn parent(&self, x: NodeIndex) -> (NodeIndex, bool) {
        if x == self.root() {
            return (NodeIndex(0), false);
        }
        let lvl = NodeIndex(x.level());
        let b = (x.0 >> (lvl.0 + 1)) & 1;
        let p = (x.0 | (1 << lvl.0)) ^ (b << (lvl.0 + 1));
        (NodeIndex(p), true)
    }

    /// Return the index of the other child of the node's parent.
    pub fn sibling(&self, x: NodeIndex) -> (NodeIndex, bool) {
        let (p, ok) = self.parent(x);
        if !ok {
            return (NodeIndex(0), false);
        }
        if x.0 < p.0 {
            p.right()
        } else {
            p.left()
        }
    }

    /// Compute the direct path of a node, ordered from leaf to root.
    pub fn direct_path(&self, mut x: NodeIndex) -> Vec<NodeIndex> {
        let mut path = vec![];
        loop {
            let (p, ok) = self.parent(x);
            if !ok {
                break;
            }
            path.push(p);
            x = p;
        }
        path
    }

    /// Compute the copath of a node, ordered from leaf to root.
    pub fn copath(&self, x: NodeIndex) -> Result<Vec<NodeIndex>> {
        let mut path = self.direct_path(x);
        if path.is_empty() {
            return Ok(vec![]);
        }
        path.insert(0, x);
        path.pop();

        let mut copath = vec![];
        for y in path {
            let (s, ok) = self.sibling(y);
            if !ok {
                return Err(Error::InvalidSibling);
            }
            copath.push(s);
        }

        Ok(copath)
    }
}

/// `NodeIndex` is the index of a node in a tree.
#[derive(Default, Debug, Hash, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeIndex(pub(crate) u32);

impl NodeIndex {
    /// Create a `NodeIndex`
    pub fn new(v: u32) -> Self {
        Self(v)
    }

    /// Return true if this is a leaf node, false if this is an intermediate
    // node.
    pub fn is_leaf(&self) -> bool {
        self.0 % 2 == 0
    }

    /// Return the index of the leaf from a node index.
    pub fn leaf_index(&self) -> (LeafIndex, bool) {
        if !self.is_leaf() {
            return (LeafIndex(0), false);
        }
        (LeafIndex(self.0 >> 1), true)
    }

    /// Return the index of the left child for an intermediate node index.
    pub fn left(&self) -> (NodeIndex, bool) {
        let lvl = self.level();
        if lvl == 0 {
            return (NodeIndex(0), false);
        }
        let l = self.0 ^ (1 << (lvl - 1));
        (NodeIndex(l), true)
    }

    /// Return the index of the right child for an intermediate node index.
    pub fn right(&self) -> (NodeIndex, bool) {
        let lvl = self.level();
        if lvl == 0 {
            return (NodeIndex(0), false);
        }
        let r = self.0 ^ (3 << (lvl - 1));
        (NodeIndex(r), true)
    }

    /// Returns the indices of the left and right children for an intermediate node index.
    pub fn children(&self) -> (NodeIndex, NodeIndex, bool) {
        let (l, ok) = self.left();
        if !ok {
            return (NodeIndex(0), NodeIndex(0), false);
        }
        let (r, _) = self.right();
        (l, r, true)
    }

    /// Return the level of a node in the tree. Leaves are at level 0, their
    /// parents are at level 1, etc.
    pub fn level(&self) -> u32 {
        if self.0 & 1 == 0 {
            return 0;
        }
        let mut lvl = 0u32;
        while (self.0 >> lvl) & 1 == 1 {
            lvl += 1;
        }
        lvl
    }
}

/// `LeafIndex` is the index of a leave in a tree.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct LeafIndex(pub(crate) u32);

impl LeafIndex {
    /// Create a `LeafIndex`
    pub fn new(v: u32) -> Self {
        Self(v)
    }

    /// Return the index of the node from a leaf index.
    pub fn node_index(&self) -> NodeIndex {
        NodeIndex(2 * self.0)
    }
}

/// Check whether input value is power of 2
pub fn is_power_of_two(x: u32) -> bool {
    x != 0 && (x & (x - 1) == 0)
}

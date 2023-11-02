use crate::raw_order::*;
use ark_bn254::Fr as Fq;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::mem::replace;
use std::rc::Rc;
use std::sync::{Arc, RwLock};

#[allow(non_snake_case)]
#[derive(Clone, Debug, PartialEq)]
enum NodeColor {
    Red,
    Black,
}
#[derive(Debug, Clone)]
pub struct Data {
    pubkey: u32,
    raw_order: Order,
    raw_order_commitment: Commitment,
}

pub struct Orderbook<T: Ord + Display + Debug + Clone + Copy> {
    bid_tree: Arc<RwLock<RBTree<T>>>,
    ask_tree: Arc<RwLock<RBTree<T>>>,
}

type LimitNode<T> = Rc<RefCell<Node<T>>>;
type LimitNodePtr<T> = Option<LimitNode<T>>;

#[derive(Clone)]
pub struct Node<T> {
    color: NodeColor,
    price: T,
    size: u32,
    value_sum: Fq,
    parent: LimitNodePtr<T>,
    left: LimitNodePtr<T>,
    right: LimitNodePtr<T>,
    orders: HashMap<u32, HashMap<Commitment, Order>>,
}

impl<T> Node<T>
where
    T: Debug + Ord + Display + Copy,
{
    pub fn new(price: T, data: Data) -> LimitNodePtr<T> {
        Some(Rc::new(RefCell::new(Node {
            color: NodeColor::Red,
            price: price,
            size: 1,
            value_sum: data.raw_order.s.p * data.raw_order.s.v,
            parent: None,
            left: None,
            right: None,
            orders: {
                let mut outer_map = HashMap::new();
                let mut inner_map = HashMap::new();
                inner_map.insert(data.raw_order_commitment, data.raw_order);
                outer_map.insert(data.pubkey, inner_map);
                outer_map
            },
        })))
    }
}

impl<T> fmt::Debug for Node<T>
where
    T: Debug + Ord + Display + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Node")
            .field("color", &self.color)
            .field("price", &self.price)
            .field("size", &self.size)
            .field("value_sum", &self.value_sum)
            .field("parent", &self.parent)
            .field("left", &self.left)
            .field("right", &self.right)
            .field("orders", &self.orders)
            .finish()
    }
}

enum Direction {
    Left,
    Right,
}

#[derive(Clone, Debug)]
pub struct RBTree<T: Ord + Display + Debug + Copy> {
    root: LimitNodePtr<T>,
    count: u32,
}

impl<T> RBTree<T>
where
    T: Ord + Display + Debug + Clone + Copy,
{
    pub fn new() -> Self {
        RBTree {
            root: None,
            count: 0,
        }
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    // 1- insert a node to the red-black tree
    pub fn insert(&mut self, price: T, data: Data) {
        // check if price level already in tree --
        // if not, add a new node at that price level
        // if yes insert <data.raw_order_commitment, data.raw_order> into the node hashmap
        if self.search(price, data.clone()).is_none() {
            // need to pass Tree<T> along with RBTree<T> or else we can't call associated functions
            let root = replace(&mut self.root, None);
            let updated_tree = self.insert_node(root, price, data);
            self.root = self.insert_fix(updated_tree.1);
        } else {
            let x = self.search(price, data.clone());
            let raw_order_clone = data.raw_order.clone();
            let mut inner_map = HashMap::new();
            inner_map.insert(data.raw_order_commitment, data.raw_order);
            x.as_ref()
                .unwrap()
                .borrow_mut()
                .orders
                .insert(data.pubkey, inner_map);
            x.as_ref().unwrap().borrow_mut().size += 1;
            x.as_ref().unwrap().borrow_mut().value_sum += raw_order_clone.s.p * raw_order_clone.s.v;
        }
    }

    fn insert_node(
        &mut self,
        tree: LimitNodePtr<T>,
        price: T,
        data: Data,
    ) -> (LimitNodePtr<T>, LimitNode<T>) {
        match tree {
            Some(tree_node) => {
                let sub_tree: LimitNode<T>;
                let node_clone = tree_node.borrow().clone();
                if price < node_clone.price {
                    let res = self.insert_node(node_clone.left, price, data);
                    let res_tree = res.0;
                    sub_tree = res.1;
                    res_tree.as_ref().unwrap().borrow_mut().parent = Some(tree_node.clone());
                    tree_node.borrow_mut().left = res_tree;
                } else {
                    let res = self.insert_node(node_clone.right, price, data);
                    let res_tree = res.0;
                    sub_tree = res.1;
                    res_tree.as_ref().unwrap().borrow_mut().parent = Some(tree_node.clone());
                    tree_node.borrow_mut().right = res_tree;
                };
                (Some(tree_node), sub_tree)
            }
            None => {
                self.count += 1;
                let added_node = Node::<T>::new(price, data);
                (added_node.clone(), added_node.unwrap())
            }
        }
    }

    fn insert_fix(&mut self, tree_node: LimitNode<T>) -> LimitNodePtr<T> {
        let mut is_root = tree_node.borrow().parent.is_none(); // if parent is none, then we have root node
        let root = if is_root {
            Some(tree_node)
        } else {
            // we don't have root node but we need to return it
            // fix our subtree and then
            // iteratively recurse up until root because we want to return it
            let mut node = tree_node.clone();
            let mut parent_clone = tree_node.borrow().parent.as_ref().unwrap().borrow().clone();
            let mut parent_color = parent_clone.color;

            while !is_root && parent_color == NodeColor::Red {
                // these are the conditions under which we want to fix the tree
                // find uncle node
                let node_clone = node.borrow().clone();
                let uncle_return = match node_clone.parent {
                    Some(parent) => {
                        let parent = parent.borrow().clone();
                        match parent.parent {
                            Some(grandparent) => {
                                let grandparent = grandparent.borrow().clone();
                                if grandparent.price < parent.price {
                                    Some((grandparent.left.clone(), Direction::Left))
                                } else {
                                    Some((grandparent.right.clone(), Direction::Right))
                                }
                            }
                            None => None,
                        }
                    }
                    None => None,
                };

                match uncle_return {
                    Some(uncle) => {
                        let uncle_node = uncle.0;
                        let side = uncle.1;

                        match side {
                            Direction::Right => {
                                let mut parent = node.borrow().parent.as_ref().unwrap().clone();
                                // uncle is on right side
                                if uncle_node.is_some()
                                    && uncle_node.as_ref().unwrap().borrow().color == NodeColor::Red
                                {
                                    // flip parent and uncle to black
                                    parent.borrow_mut().color = NodeColor::Black;
                                    uncle_node.unwrap().borrow_mut().color = NodeColor::Black;
                                    // flip grandparent to red
                                    parent.borrow().parent.as_ref().unwrap().borrow_mut().color =
                                        NodeColor::Red;
                                    // iteratively recurse up tree to check for any other red-black violations
                                    node = parent.borrow().clone().parent.clone().unwrap();
                                } else {
                                    // uncle is black (None counts as black too)
                                    // need to know whether current node is either on left or right side
                                    if parent.borrow().clone().price < node.borrow().clone().price {
                                        // node is on right side
                                        // rotate node left so that node becomes parent and parent becomes left child of node
                                        let parent_tmp =
                                            node.borrow().parent.as_ref().unwrap().clone();
                                        node = parent_tmp;
                                        self.rotate_left(node.clone());
                                        parent = node.borrow().parent.as_ref().unwrap().clone();
                                    }

                                    parent.borrow_mut().color = NodeColor::Black;
                                    parent.borrow().parent.as_ref().unwrap().borrow_mut().color =
                                        NodeColor::Red;
                                    let grandparent = node
                                        .borrow()
                                        .parent
                                        .as_ref()
                                        .unwrap()
                                        .borrow()
                                        .parent
                                        .as_ref()
                                        .unwrap()
                                        .clone();
                                    // rotate parent right so that grandparent becomes right child
                                    self.rotate_right(grandparent);
                                }
                            }
                            Direction::Left => {
                                let mut parent = node.borrow().parent.as_ref().unwrap().clone();
                                // uncle is on left side
                                if uncle_node.is_some()
                                    && uncle_node.as_ref().unwrap().borrow().color == NodeColor::Red
                                {
                                    // flip parent and uncle to black
                                    parent.borrow_mut().color = NodeColor::Black;
                                    uncle_node.unwrap().borrow_mut().color = NodeColor::Black;
                                    // flip grandparent to red
                                    parent.borrow().parent.as_ref().unwrap().borrow_mut().color =
                                        NodeColor::Red;
                                    // iteratively recurse up tree to check for any other red-black violations
                                    node = parent.borrow().clone().parent.clone().unwrap();
                                } else {
                                    // uncle is black
                                    // need to know whether current node is either left or right child of parent
                                    if parent.borrow().clone().price > node.borrow().clone().price {
                                        // node is on left side
                                        // rotate node right so that node becomes parent and parent becomes right child of node
                                        let parent_tmp =
                                            node.borrow().parent.as_ref().unwrap().clone();
                                        node = parent_tmp;
                                        self.rotate_right(node.clone());
                                        parent = node.borrow().parent.as_ref().unwrap().clone();
                                    }
                                    parent.borrow_mut().color = NodeColor::Black;
                                    parent.borrow().parent.as_ref().unwrap().borrow_mut().color =
                                        NodeColor::Red;
                                    let grandparent = node
                                        .borrow()
                                        .parent
                                        .as_ref()
                                        .unwrap()
                                        .borrow()
                                        .parent
                                        .as_ref()
                                        .unwrap()
                                        .clone();
                                    self.rotate_left(grandparent);
                                }
                            }
                        }
                    }
                    None => {
                        break;
                    }
                }
                is_root = node.borrow().parent.is_none();
                if !is_root {
                    parent_clone = node.borrow().parent.as_ref().unwrap().borrow().clone();
                    parent_color = parent_clone.color;
                }
            }

            // done fixing the tree, so recurse back up the tree and return root
            while node.borrow().parent.is_some() {
                let p = node.borrow().parent.as_ref().unwrap().clone();
                node = p;
            }
            Some(node)
        };
        root.as_ref().unwrap().borrow_mut().color = NodeColor::Black;
        root
    }

    fn rotate_left(&self, tree_node: LimitNode<T>) {
        let cur_parent = tree_node;
        let right_child = cur_parent.borrow().right.clone();

        // take the left child of right child and make it the right child of the current parent
        cur_parent.borrow_mut().right = match right_child {
            Some(ref right_child) => right_child.borrow().left.clone(),
            None => None,
        };

        if right_child.is_some() {
            // make right child's parent the current grandparent
            right_child.as_ref().unwrap().borrow_mut().parent = cur_parent.borrow().parent.clone();
            if right_child.as_ref().unwrap().borrow().left.is_some() {
                // make right_child's left child's parent the current parent
                let l = right_child.as_ref().unwrap().borrow().left.clone();
                l.unwrap().borrow_mut().parent = Some(cur_parent.clone());
            }
        }

        match cur_parent.borrow().clone().parent {
            Some(grandparent) => {
                if grandparent.borrow().clone().price < cur_parent.borrow().clone().price {
                    grandparent.borrow_mut().right = right_child.clone();
                } else {
                    grandparent.borrow_mut().left = right_child.clone();
                }
            }
            None => {
                // grandparent is None, so make the right_child's parent None
                right_child.as_ref().unwrap().borrow_mut().parent = None;
            }
        }
        // make right_child's left child equal to the parent
        right_child.as_ref().unwrap().borrow_mut().left = Some(cur_parent.clone());
        // make parent's parent equal to right_child
        cur_parent.borrow_mut().parent = right_child.clone();
    }

    fn rotate_right(&self, tree_node: LimitNode<T>) {
        let cur_parent = tree_node;
        let left_child = cur_parent.borrow().left.clone();

        // take the right child of left_child and make it the left child of current parent
        cur_parent.borrow_mut().left = match left_child {
            Some(ref left_child) => left_child.borrow().right.clone(),
            None => None,
        };

        if left_child.is_some() {
            // make left child's parent the current grandparent
            left_child.as_ref().unwrap().borrow_mut().parent = cur_parent.borrow().parent.clone();
            if left_child.as_ref().unwrap().borrow().right.is_some() {
                // make left_child's right child's parent the current parent
                let r = left_child.as_ref().unwrap().borrow().right.clone();
                r.unwrap().borrow_mut().parent = Some(cur_parent.clone());
            }
        }

        match cur_parent.borrow().clone().parent {
            Some(grandparent) => {
                if grandparent.borrow().clone().price < cur_parent.borrow().clone().price {
                    grandparent.borrow_mut().right = left_child.clone();
                } else {
                    grandparent.borrow_mut().left = left_child.clone();
                }
            }
            None => {
                // grandparent is None, so make the left_child's parent None
                left_child.as_ref().unwrap().borrow_mut().parent = None;
            }
        }
        // make left_child's right child equal to the parent
        left_child.as_ref().unwrap().borrow_mut().right = Some(cur_parent.clone());
        // make parent's parent equal to left_child
        cur_parent.borrow_mut().parent = left_child.clone();
    }

    pub fn search(&self, key: T, data: Data) -> LimitNodePtr<T> {
        let dummy = Node::<T>::new(key, data).unwrap().borrow().clone();
        self.search_node(&self.root, &dummy)
    }

    fn search_node(&self, tree_node: &LimitNodePtr<T>, node: &Node<T>) -> LimitNodePtr<T> {
        match tree_node {
            Some(sub_tree) => {
                let sub_tree_clone = sub_tree.borrow().clone();
                if sub_tree_clone.price == node.price {
                    Some(sub_tree.clone())
                } else {
                    if sub_tree_clone.price > node.price {
                        self.search_node(&sub_tree_clone.left, node)
                    } else {
                        self.search_node(&sub_tree_clone.right, node)
                    }
                }
            }
            None => None,
        }
    }

    // 2- delete a node from the red-black tree
    // the whole node is deleted if  there is only one order remaining in the hashmap
    // else only the order is removed from the hashmap
    pub fn delete(&mut self, key: T, data: Data) {
        let z = self.search(key, data.clone());
        if z.is_none() {
            println!("Key not found");
            return;
        }
        if z.as_ref().unwrap().borrow().clone().size == 1 {
            // key exists
            let u = z; // node to be deleted
            let p = u.as_ref().unwrap().borrow().parent.clone();
            let v = u.as_ref().unwrap().borrow().left.clone();
            let w = u.as_ref().unwrap().borrow().right.clone();

            let mut side = Direction::Left; // set default value to left

            if p.is_some() {
                side = if p.as_ref().unwrap().borrow().clone().price
                    > u.as_ref().unwrap().borrow().clone().price
                {
                    Direction::Right
                } else {
                    Direction::Left
                };
            }

            let mut u_original_color = u.as_ref().unwrap().borrow().color.clone();
            let x: LimitNodePtr<T>;

            if v.is_none() {
                // left node of u is none
                x = w.clone();
                self.transplant(u.clone(), w.clone());
            } else if w.is_none() {
                // right node of u is none
                x = v.clone();
                self.transplant(u.clone(), v.clone());
            } else {
                // both left and right nodes exist
                // find minimum in right branch to replace u
                let y = self.find_min(w.clone());
                // y will always be Some since we only call find_min where left and right both exist
                // if w has no children then find_min will simply return w
                // we can safely unwrap
                // x is right subtree of y
                u_original_color = y.as_ref().unwrap().borrow().color.clone();
                x = y.as_ref().unwrap().borrow().clone().right;
                if y.as_ref()
                    .unwrap()
                    .borrow()
                    .clone()
                    .parent
                    .as_ref()
                    .unwrap()
                    .borrow()
                    .clone()
                    .price
                    == u.as_ref().unwrap().borrow().clone().price
                {
                    if x.is_some() {
                        x.as_ref().unwrap().borrow_mut().parent = y.clone();
                    }
                } else {
                    self.transplant(y.clone(), y.as_ref().unwrap().borrow().right.clone());
                    y.as_ref().unwrap().borrow_mut().right =
                        u.as_ref().unwrap().borrow().right.clone();
                    y.as_ref()
                        .unwrap()
                        .borrow()
                        .right
                        .as_ref()
                        .unwrap()
                        .borrow_mut()
                        .parent = y.clone();
                }
                self.transplant(u.clone(), y.clone());
                y.as_ref().unwrap().borrow_mut().left = v.clone();
                v.as_ref().unwrap().borrow_mut().parent = y.clone();
                y.as_ref().unwrap().borrow_mut().color = u.as_ref().unwrap().borrow().color.clone();
            }
            if u_original_color == NodeColor::Black {
                self.delete_fix(x.clone(), p.clone(), side);
            }
            self.count -= 1;
        } else {
            if let Some(inner_map) = z.as_ref().unwrap().borrow_mut().orders.get_mut(&data.pubkey) {
                inner_map.remove(&data.raw_order_commitment);
            }
            z.as_ref().unwrap().borrow_mut().size -= 1;
        }
    }

    fn delete_fix(&mut self, x: LimitNodePtr<T>, p: LimitNodePtr<T>, side: Direction) {
        // x color is true if black and false if red
        let mut x_color = if x.is_some() {
            x.as_ref().unwrap().borrow().clone().color == NodeColor::Black
        } else {
            // Node is none so it is black
            true
        };
        let mut cur_p = p;
        let mut cur_x = x;
        let mut is_root = cur_p.is_none();
        while !is_root && x_color {
            match side {
                Direction::Right => {
                    // sibling on the right side of p
                    // cur_p exists or else we wouldnt be in this while loop
                    let mut s = cur_p.as_ref().unwrap().borrow().right.clone();
                    if s.is_some() {
                        if s.as_ref().unwrap().borrow().clone().color == NodeColor::Red {
                            // DB's sibling is red
                            // swap color of p with s
                            // rotate parent node left
                            s.as_ref().unwrap().borrow_mut().color = NodeColor::Black;
                            cur_p.as_ref().unwrap().borrow_mut().color = NodeColor::Red;
                            self.rotate_left(cur_p.as_ref().unwrap().clone());
                            s = cur_p.as_ref().unwrap().borrow().right.clone();
                        }
                        let s_left = s.as_ref().unwrap().borrow().clone().left.clone();
                        let s_right = s.as_ref().unwrap().borrow().clone().right.clone();

                        let s_left_color = if s_left.is_some() {
                            s_left.as_ref().unwrap().borrow().clone().color == NodeColor::Black
                        } else {
                            true
                        };

                        let s_right_color = if s_right.is_some() {
                            s_right.as_ref().unwrap().borrow().clone().color == NodeColor::Black
                        } else {
                            true
                        };

                        if s_left_color && s_right_color {
                            s.as_ref().unwrap().borrow_mut().color = NodeColor::Red;
                            cur_x = cur_p.clone();
                            let g = cur_p.as_ref().unwrap().borrow().clone().parent.clone();
                            cur_p = g.clone();
                            x_color = if cur_x.is_some() {
                                cur_x.as_ref().unwrap().borrow().clone().color == NodeColor::Black
                            } else {
                                true
                            };
                        } else {
                            if s_right.is_some()
                                && s_right.as_ref().unwrap().borrow().clone().color
                                    == NodeColor::Black
                            {
                                if s_left.is_some() {
                                    s_left.as_ref().unwrap().borrow_mut().color = NodeColor::Black;
                                    s.as_ref().unwrap().borrow_mut().color = NodeColor::Red;
                                    self.rotate_right(s.unwrap());
                                    s = cur_p.as_ref().unwrap().borrow().right.clone();
                                }
                            }
                            s.as_ref().unwrap().borrow_mut().color =
                                cur_p.as_ref().unwrap().borrow().color.clone();
                            cur_p.as_ref().unwrap().borrow_mut().color = NodeColor::Black;
                            if s_right.is_some() {
                                s_right.as_ref().unwrap().borrow_mut().color = NodeColor::Black;
                            }
                            self.rotate_left(cur_p.as_ref().unwrap().clone());
                            is_root = true;
                        }
                    }
                }
                Direction::Left => {
                    // siblings are on the left side of p
                    let mut s = cur_p.as_ref().unwrap().borrow().left.clone();
                    if s.is_some() {
                        if s.as_ref().unwrap().borrow().clone().color == NodeColor::Red {
                            // DB's sibling is red
                            // swap color of p with s
                            // rotate parent node right
                            s.as_ref().unwrap().borrow_mut().color = NodeColor::Black;
                            cur_p.as_ref().unwrap().borrow_mut().color = NodeColor::Red;
                            self.rotate_right(cur_p.as_ref().unwrap().clone());
                            s = cur_p.as_ref().unwrap().borrow().left.clone();
                        }
                        let s_left = s.as_ref().unwrap().borrow().clone().left.clone();
                        let s_right = s.as_ref().unwrap().borrow().clone().right.clone();

                        let s_left_color = if s_left.is_some() {
                            s_left.as_ref().unwrap().borrow().clone().color == NodeColor::Black
                        } else {
                            true
                        };

                        let s_right_color = if s_right.is_some() {
                            s_right.as_ref().unwrap().borrow().clone().color == NodeColor::Black
                        } else {
                            true
                        };

                        if s_left_color && s_right_color {
                            s.as_ref().unwrap().borrow_mut().color = NodeColor::Red;
                            cur_x = cur_p.clone();
                            let g = cur_p.as_ref().unwrap().borrow().clone().parent.clone();
                            cur_p = g.clone();
                            x_color = if cur_x.is_some() {
                                cur_x.as_ref().unwrap().borrow().clone().color == NodeColor::Black
                            } else {
                                true
                            };
                        } else {
                            if s_right.is_some()
                                && s_right.as_ref().unwrap().borrow().clone().color
                                    == NodeColor::Black
                            {
                                if s_left.is_some() {
                                    s_left.as_ref().unwrap().borrow_mut().color = NodeColor::Black;
                                    s.as_ref().unwrap().borrow_mut().color = NodeColor::Red;
                                    self.rotate_left(s.unwrap());
                                    s = cur_p.as_ref().unwrap().borrow().left.clone();
                                }
                            }
                            s.as_ref().unwrap().borrow_mut().color =
                                cur_p.as_ref().unwrap().borrow().color.clone();
                            cur_p.as_ref().unwrap().borrow_mut().color = NodeColor::Black;
                            if s_left.is_some() {
                                s_left.as_ref().unwrap().borrow_mut().color = NodeColor::Black;
                            }
                            self.rotate_right(cur_p.as_ref().unwrap().clone());
                            is_root = true;
                        }
                    }
                }
            }
        }
        if cur_x.is_some() {
            cur_x.as_ref().unwrap().borrow_mut().color = NodeColor::Black;
        }
    }

    fn transplant(&mut self, z: LimitNodePtr<T>, v: LimitNodePtr<T>) {
        // transplant is responsible for deleting u and replacing it with v
        let u = z.unwrap();
        let u_p = u.borrow().parent.clone();
        if u_p.is_none() {
            // deleting root node
            self.root = v.clone();
        } else {
            if u_p.as_ref().unwrap().borrow().clone().price > u.borrow().clone().price {
                // z is on the left of parent
                u_p.as_ref().unwrap().borrow_mut().left = v.clone();
            } else {
                // z is on the right of parent
                u_p.as_ref().unwrap().borrow_mut().right = v.clone();
            }
        }
        if v.is_some() {
            // replacement node exists
            v.as_ref().unwrap().borrow_mut().parent = u_p.clone();
        }
    }

    fn find_min(&self, tree: LimitNodePtr<T>) -> LimitNodePtr<T> {
        match tree {
            Some(sub_tree) => {
                let mut left = Some(sub_tree.clone());
                while left.as_ref().unwrap().borrow().left.clone().is_some() {
                    left = left.unwrap().borrow().left.clone();
                }
                left
            }
            None => tree,
        }
    }

    fn find_max(&self, tree: LimitNodePtr<T>) -> LimitNodePtr<T> {
        match tree {
            Some(sub_tree) => {
                let mut right = Some(sub_tree.clone());
                while right.as_ref().unwrap().borrow().right.clone().is_some() {
                    right = right.unwrap().borrow().right.clone();
                }
                right
            }
            None => tree,
        }
    }

    // 3- count the number of leaves in a tree
    pub fn leaves(&self) -> u32 {
        if self.root.is_none() {
            return 0;
        }
        let root = self.root.as_ref().unwrap().clone();
        let mut stack: Vec<LimitNodePtr<T>> = Vec::new();
        stack.push(Some(root));

        let mut count = 0;
        while !stack.is_empty() {
            let node = stack.pop();
            let mut node_left = None;
            let mut node_right = None;

            if node.is_some() {
                node_left = node
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .borrow()
                    .clone()
                    .left
                    .clone();
                node_right = node
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .borrow()
                    .clone()
                    .right
                    .clone();
            }

            if node_left.is_some() {
                stack.push(node_left.clone());
            }

            if node_right.is_some() {
                stack.push(node_right.clone());
            }

            if node_left.is_none() && node_right.is_none() {
                count += 1;
            }
        }
        count
    }

    // 4- return the height of a tree
    pub fn height(&self) -> u32 {
        if self.root.is_none() {
            return 0;
        }
        let root = self.root.as_ref().unwrap().clone();
        let mut queue: VecDeque<LimitNodePtr<T>> = VecDeque::new();
        queue.push_back(Some(root));

        let mut height = 0;
        // find height by breadth first search traversal
        while !queue.is_empty() {
            let n = queue.len();
            for _ in 0..n {
                let node = queue.pop_front().unwrap().unwrap();
                for child in [node.borrow().left.clone(), node.borrow().right.clone()] {
                    if child.is_some() {
                        queue.push_back(child);
                    }
                }
            }
            height += 1;
        }
        height
    }

    // 5- print in-order traversal of tree
    pub fn print_inorder(&self) {
        if self.root.is_none() {
            println!("None");
            return;
        }
        let mut root = self.root.clone();
        let mut stack: Vec<LimitNodePtr<T>> = Vec::new();
        while !stack.is_empty() || !root.is_none() {
            if root.is_some() {
                stack.push(root.clone());
                let p = root.as_ref().unwrap().borrow().left.clone();
                root = p.clone();
            } else {
                let pop = stack.pop().unwrap();
                print!(" {} ", pop.as_ref().unwrap().borrow().price.clone());
                root = pop.as_ref().unwrap().borrow().right.clone();
            }
        }
        println!("\n");
    }

    pub fn print_preorder(&self) {
        if self.root.is_none() {
            println!("None");
            return;
        }
        let mut root = self.root.clone();
        let mut stack: Vec<LimitNodePtr<T>> = Vec::new();
        stack.push(root);
        let mut cur: LimitNodePtr<T>;
        while !stack.is_empty() {
            cur = stack.pop().unwrap();
            root = cur.clone();
            print!(" {} ", root.as_ref().unwrap().borrow().price.clone());
            let root_right = root.as_ref().unwrap().borrow().right.clone();
            let root_left = root.as_ref().unwrap().borrow().left.clone();
            if root_right.is_some() {
                stack.push(root_right.clone());
            }
            if root_left.is_some() {
                stack.push(root_left.clone());
            }
        }
        println!("\n");
    }

    pub fn print_levelorder(&self) {
        if self.root.is_none() {
            println!("None");
            return;
        };
        let inorder_nodes = self.inorder();
        for node in inorder_nodes {
            print!(" {} ", node.unwrap().borrow().price.clone());
        }
        println!("\n");
    }

    pub fn min(&self) -> LimitNodePtr<T> {
        self.find_min(self.root.clone())
    }

    pub fn max(&self) -> LimitNodePtr<T> {
        self.find_max(self.root.clone())
    }

    fn inorder(&self) -> VecDeque<LimitNodePtr<T>> {
        let root = self.root.as_ref().unwrap().clone();
        let mut queue: VecDeque<LimitNodePtr<T>> = VecDeque::new();
        queue.push_back(Some(root));
        let mut res: VecDeque<LimitNodePtr<T>> = VecDeque::new();
        while !queue.is_empty() {
            let n = queue.len();
            for _ in 0..n {
                let node = queue.pop_front().unwrap().unwrap();
                res.push_back(Some(node.clone()));
                for child in [node.borrow().left.clone(), node.borrow().right.clone()] {
                    if child.is_some() {
                        queue.push_back(child);
                    }
                }
            }
        }
        res
    }
}

impl<T> fmt::Display for RBTree<T>
where
    T: Debug + Ord + Display + Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RBTree")
            .field("root", &self.root)
            .field("count", &self.count)
            .finish()
    }
}




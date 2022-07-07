use libafl::{bolts::tuples::Named, executors::ExitKind, observers::Observer, Error};
use serde::{Deserialize, Serialize};
use std::cmp::Ord;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

#[inline]
fn pack_transition(from: u32, to: u32) -> u64 {
    (from as u64) << 32 | (to as u64)
}

#[inline]
fn unpack_transition(transition: u64) -> (u32, u32) {
    ((transition >> 32) as u32, transition as u32)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "PS: serde::Serialize + for<'a> serde::Deserialize<'a>")]
struct StateGraph<PS>
where
    PS: Clone + Debug + Ord,
{
    nodes: BTreeMap<PS, u32>,
    edges: BTreeSet<u64>,
    last_node: Option<u32>,
    new_transitions: bool,
}
impl<PS> StateGraph<PS>
where
    PS: Clone + Debug + Ord + Serialize + for<'a> Deserialize<'a>,
{
    fn new() -> Self {
        Self {
            nodes: BTreeMap::<PS, u32>::new(),
            edges: BTreeSet::<u64>::new(),
            last_node: None,
            new_transitions: false,
        }
    }

    fn reset(&mut self) {
        self.last_node = None;
        self.new_transitions = false;
    }

    fn add_node(&mut self, state: &PS) -> u32 {
        match self.nodes.get(state) {
            Some(id) => *id,
            None => {
                let next_id = self.nodes.len() as u32;
                assert!(self.nodes.insert(state.clone(), next_id).is_none());
                next_id
            },
        }
    }

    fn add_edge(&mut self, id: u32) {
        self.new_transitions |= match self.last_node.take() {
            Some(old_id) => {
                if old_id != id {
                    self.edges.insert(pack_transition(old_id, id))
                } else {
                    false
                }
            },
            None => false,
        };

        self.last_node = Some(id);
    }

    fn print_dot(&self) {
        println!("digraph IMPLEMENTED_STATE_MACHINE {{");

        for value in &self.edges {
            let (from, to) = unpack_transition(*value);
            println!("  \"{}\" -> \"{}\";", from, to);
        }

        println!("}}");
    }
}

/// An observer that builds a state-graph.
///
/// The states that this observer stores must implement
/// the following traits: [`Ord`](core::cmp::Ord), [`Debug`](core::fmt::Debug), [`Clone`](core::clone::Clone), [`Serialize`](serde::Serialize), [`Deserialize`](serde::Deserialize).
/// Most commonly used state types are u64 or [u8; N].
///
/// When you create a StateObserver always specify `PS` manually:
/// ```
/// type State = u64;
/// let observer = StateObserver::<State>::new("state observer");
/// ```
///
/// The executor is responsible for calling [`StateObserver::record()`](crate::StateObserver::record)
/// with states inferred from the fuzz target.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "PS: serde::Serialize + for<'a> serde::Deserialize<'a>")]
pub struct StateObserver<PS>
where
    PS: Clone + Debug + Ord,
{
    name: String,
    graph: StateGraph<PS>,
}

impl<PS> StateObserver<PS>
where
    PS: Clone + Debug + Ord + Serialize + for<'a> Deserialize<'a>,
{
    /// Create a new StateObserver with a given name.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            graph: StateGraph::<PS>::new(),
        }
    }

    /// Tell the observer that the target has entered state `state`.
    pub fn record(&mut self, state: &PS) {
        let node = self.graph.add_node(state);
        self.graph.add_edge(node);
    }

    /// Returns whether any new edges were created in the state-graph during the last run.
    /// Used by [`StateFeedback`](crate::StateFeedback).
    pub fn had_new_transitions(&self) -> bool {
        self.graph.new_transitions
    }

    /// Returns the number of vertices and edges in the state-graph.
    /// Used by [`StateFeedback`](crate::StateFeedback).
    pub fn info(&self) -> (usize, usize) {
        (self.graph.nodes.len(), self.graph.edges.len())
    }

    /// Print a dot representation of the statemachine to stdout.
    pub fn print_statemachine(&self) {
        self.graph.print_dot();
    }
}

impl<PS> Named for StateObserver<PS>
where
    PS: Clone + Debug + Ord + Serialize + for<'a> Deserialize<'a>,
{
    fn name(&self) -> &str {
        &self.name
    }
}

impl<PS, I, S> Observer<I, S> for StateObserver<PS>
where
    PS: Clone + Debug + Ord + Serialize + for<'a> Deserialize<'a>,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.graph.reset();
        Ok(())
    }

    fn post_exec(&mut self, _state: &mut S, _input: &I, _exit_kind: &ExitKind) -> Result<(), Error> {
        Ok(())
    }
}

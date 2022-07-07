use libafl::{
    Error,
    state::HasRand,
    mutators::{
        Mutator,
        MutationResult,
    },
    inputs::Input,
    bolts::{
        rands::Rand,
        HasLen,
        tuples::Named,
    },
};
use std::marker::PhantomData;
use crate::input::HasPackets;

/// A mutator that duplicates a single, random packet.
///
/// It respects an upper bound on the number of packets
/// passed as an argument to the constructor.
///
/// # Example
/// ```
/// // Make sure that we never exceed 16 packets in an input
/// let mutator = PacketDuplicateMutator::new(16);
/// ```
pub struct PacketDuplicateMutator<P>
where
    P: Clone,
{
    max_packets: usize,
    phantom: PhantomData<P>,
}

impl<P> PacketDuplicateMutator<P>
where
    P: Clone,
{
    pub fn new(max_packets: usize) -> Self {
        Self {
            max_packets,
            phantom: PhantomData,
        }
    }
}

impl<I, S, P> Mutator<I, S> for PacketDuplicateMutator<P>
where
    P: Clone,
    I: Input + HasLen + HasPackets<P>,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<MutationResult, Error> {
        if input.len() >= self.max_packets {
            return Ok(MutationResult::Skipped);
        }
        
        let from = state.rand_mut().below(input.len() as u64) as usize;
        let to = state.rand_mut().below(input.len() as u64 + 1) as usize;
        
        if from == to {
            return Ok(MutationResult::Skipped);
        }
        
        let copy = input.packets()[from].clone();
        input.packets_mut().insert(to, copy);
        
        Ok(MutationResult::Mutated)
    }
}

impl<P> Named for PacketDuplicateMutator<P>
where
    P: Clone,
{
    fn name(&self) -> &str {
        "PacketDuplicateMutator"
    }
}

use libafl::{
    Error,
    state::{HasRand, HasMaxSize},
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

/// A mutator that deletes a single, random packet.
///
/// It respects a lower bound on the number of packets
/// passed as an argument to the constructor.
///
/// # Example
/// ```
/// // Make sure that we always have at least 4 packets in an input
/// let mutator = PacketDeleteMutator::new(4);
/// ```
pub struct PacketDeleteMutator<P> {
    phantom: PhantomData<P>,
    min_packets: usize,
}

impl<P> PacketDeleteMutator<P> {
    pub fn new(min_packets: usize) -> Self {
        Self {
            phantom: PhantomData,
            min_packets: std::cmp::max(1, min_packets),
        }
    }
}

impl<I, S, P> Mutator<I, S> for PacketDeleteMutator<P>
where
    I: Input + HasLen + HasPackets<P>,
    S: HasRand + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<MutationResult, Error> {
        if input.len() <= self.min_packets {
            return Ok(MutationResult::Skipped);
        }
        
        let idx = state.rand_mut().below(input.len() as u64) as usize;
        input.packets_mut().remove(idx);
        
        Ok(MutationResult::Mutated)
    }
}

impl<P> Named for PacketDeleteMutator<P> {
    fn name(&self) -> &str {
        "PacketDeleteMutator"
    }
}

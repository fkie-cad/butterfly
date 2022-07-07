use crate::input::HasPackets;
use libafl::{
    bolts::{rands::Rand, tuples::Named, HasLen},
    inputs::Input,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};
use std::marker::PhantomData;

/// A mutator that swaps two random packets.
pub struct PacketReorderMutator<P> {
    phantom: PhantomData<P>,
}

impl<P> PacketReorderMutator<P> {
    /// Create a new PacketReorderMutator
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<I, S, P> Mutator<I, S> for PacketReorderMutator<P>
where
    I: Input + HasLen + HasPackets<P>,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<MutationResult, Error> {
        if input.len() <= 1 {
            return Ok(MutationResult::Skipped);
        }

        let from = state.rand_mut().below(input.len() as u64) as usize;
        let to = state.rand_mut().below(input.len() as u64) as usize;

        if from == to {
            return Ok(MutationResult::Skipped);
        }

        input.packets_mut().swap(from, to);

        Ok(MutationResult::Mutated)
    }
}

impl<P> Named for PacketReorderMutator<P> {
    fn name(&self) -> &str {
        "PacketReorderMutator"
    }
}

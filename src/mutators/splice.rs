use libafl::{
    Error,
    state::{HasRand, HasMaxSize},
    mutators::{
        Mutator,
        MutationResult,
    },
    inputs::{
        Input,
        HasBytesVec,
    },
    bolts::{
        rands::Rand,
        HasLen,
        tuples::Named,
    },
};
use std::marker::PhantomData;
use crate::input::HasPackets;

pub struct PacketSpliceMutator<P>
where
    P: HasBytesVec + HasLen,
{
    phantom: PhantomData<P>,
    min_packets: usize,
}

impl<P> PacketSpliceMutator<P>
where
    P: HasBytesVec + HasLen,
{
    pub fn new(min_packets: usize) -> Self {
        Self {
            phantom: PhantomData,
            min_packets: std::cmp::max(1, min_packets),
        }
    }
}

impl<I, S, P> Mutator<I, S> for PacketSpliceMutator<P>
where
    P: HasBytesVec + HasLen,
    I: Input + HasLen + HasPackets<P>,
    S: HasRand + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<MutationResult, Error> {
        if input.len() <= self.min_packets {
            return Ok(MutationResult::Skipped);
        }
        
        let idx = state.rand_mut().below(input.len() as u64 - 1) as usize;
        let packet = input.packets_mut().remove(idx + 1);
        
        let to = state.rand_mut().below(input.packets()[idx].len() as u64) as usize;
        let from = state.rand_mut().below(packet.len() as u64) as usize;
        
        input.packets_mut()[idx].bytes_mut().resize(to + 1 + packet.len() - (from + 1), 0);
        input.packets_mut()[idx].bytes_mut()[to..].copy_from_slice(&packet.bytes()[from..]);
        
        let bytes = input.packets_mut()[idx].bytes_mut();
        
        if bytes.len() > state.max_size() {
            bytes.resize(state.max_size(), 0);
        }
        
        Ok(MutationResult::Mutated)
    }
}

impl<P> Named for PacketSpliceMutator<P>
where
    P: HasBytesVec + HasLen,
{
    fn name(&self) -> &str {
        "PacketSpliceMutator"
    }
}

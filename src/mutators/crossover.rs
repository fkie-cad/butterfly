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

/// Like libafls [`CrossoverInsertMutator`](libafl::mutators::mutations::CrossoverInsertMutator)
/// but for a single packet.
///
/// `P` denotes the type of an individual packet that MUST implement [`HasBytesVec`](libafl::inputs::HasBytesVec).    
/// If a packet cannot simply be represented as a bytearray then this mutator cannot be used.
pub struct PacketCrossoverInsertMutator<P>
where
    P: HasBytesVec + HasLen,
{
    phantom: PhantomData<P>,
}

impl<P> PacketCrossoverInsertMutator<P>
where
    P: HasBytesVec + HasLen,
{
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<I, S, P> Mutator<I, S> for PacketCrossoverInsertMutator<P>
where
    P: HasBytesVec + HasLen,
    I: Input + HasLen + HasPackets<P>,
    S: HasRand + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<MutationResult, Error> {
        if input.len() <= 1 {
            return Ok(MutationResult::Skipped);
        }
        
        let max_size = state.max_size();
        
        let packet = state.rand_mut().below(input.len() as u64) as usize;
        let packet_len = input.packets()[packet].len();
        let other = state.rand_mut().below(input.len() as u64) as usize;
        let other_len = input.packets()[other].len();
        
        if packet == other || packet_len >= max_size || packet_len == 0 || other_len == 0 {
            return Ok(MutationResult::Skipped);
        }
        
        let from = state.rand_mut().below(other_len as u64) as usize;
        let to = state.rand_mut().below(packet_len as u64) as usize;
        let mut len = 1 + state.rand_mut().below((other_len - from) as u64) as usize;
        
        // Don't exceed the maximum size of a packet
        if packet_len + len > max_size {
            len = max_size - packet_len;
        }
        
        // Make room for `len` additional bytes
        input.packets_mut()[packet].bytes_mut().resize(packet_len + len, 0);
        
        // Move bytes at `to`, `len` places to the right
        input.packets_mut()[packet].bytes_mut().copy_within(to..packet_len, to + len);
        
        // Insert `len` bytes from `other` into `packet`
        let content = input.packets()[other].bytes()[from..from + len].to_vec();
        input.packets_mut()[packet].bytes_mut()[to..to + len].copy_from_slice(&content);
        
        Ok(MutationResult::Mutated)
    }
}

impl<P> Named for PacketCrossoverInsertMutator<P>
where
    P: HasBytesVec + HasLen,
{
    fn name(&self) -> &str {
        "PacketCrossoverInsertMutator"
    }
}

/// Like libafls [`CrossoverReplaceMutator`](libafl::mutators::mutations::CrossoverReplaceMutator)
/// but for a single packet.
///
/// `P` denotes the type of an individual packet that MUST implement [`HasBytesVec`](libafl::inputs::HasBytesVec).    
/// If a packet cannot simply be represented as a bytearray then this mutator cannot be used.
pub struct PacketCrossoverReplaceMutator<P>
where
    P: HasBytesVec + HasLen,
{
    phantom: PhantomData<P>,
}

impl<P> PacketCrossoverReplaceMutator<P>
where
    P: HasBytesVec + HasLen,
{
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<I, S, P> Mutator<I, S> for PacketCrossoverReplaceMutator<P>
where
    P: HasBytesVec + HasLen,
    I: Input + HasLen + HasPackets<P>,
    S: HasRand + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<MutationResult, Error> {
        if input.len() <= 1 {
            return Ok(MutationResult::Skipped);
        }
        
        let packet = state.rand_mut().below(input.len() as u64) as usize;
        let packet_len = input.packets()[packet].len();
        let other = state.rand_mut().below(input.len() as u64) as usize;
        let other_len = input.packets()[other].len();
        
        if packet == other || packet_len == 0 || other_len == 0 {
            return Ok(MutationResult::Skipped);
        }
        
        let from = state.rand_mut().below(other_len as u64) as usize;
        let to = state.rand_mut().below(packet_len as u64) as usize;
        let len = state.rand_mut().below(std::cmp::min(other_len - from, packet_len - to) as u64) as usize;
        
        let content = input.packets()[other].bytes()[from..from + len].to_vec();
        input.packets_mut()[packet].bytes_mut()[to..to + len].copy_from_slice(&content);
        
        Ok(MutationResult::Mutated)
    }
}

impl<P> Named for PacketCrossoverReplaceMutator<P>
where
    P: HasBytesVec + HasLen,
{
    fn name(&self) -> &str {
        "PacketCrossoverReplaceMutator"
    }
}

use crate::input::HasPackets;
use libafl::{
    bolts::{rands::Rand, tuples::Named, HasLen},
    inputs::{BytesInput, HasBytesVec, Input},
    mutators::{MutationResult, Mutator},
    state::{HasMaxSize, HasRand},
    Error,
};
use std::marker::PhantomData;

/// Signifies that a packet type supports the [`PacketCrossoverInsertMutator`] mutator.    
///
/// If you want to use the [`PacketCrossoverInsertMutator`] your Input type must have
/// a vector of packets that implement this trait.
/// IMPORTANT: This must be implemented on the packet type, not the input type.
///
/// Already implemented for
/// - [`BytesInput`](libafl::inputs::BytesInput)
///
/// # Example
/// Suppose we have the following packet type
/// ```
/// enum PacketType {
///    A(BytesInput),
///    B(BytesInput),
/// }
/// ```
/// Then we can implement this trait as follows
/// ```
/// impl<S> HasCrossoverInsertMutation<S> for PacketType
/// where
///    S: HasRand + HasMaxSize,
/// {
///    fn mutate_crossover_insert(&mut self, state: &mut S, other: &Self, stage_idx: i32) -> Result<MutationResult, Error> {
///        match self {
///            PacketType::A(data) => {
///                match other {
///                    PacketType::A(other_data) => data.mutate_crossover_insert(state, other_data, stage_idx),
///                    PacketType::B(_) => Ok(MutationResult::Skipped),
///                }
///            },
///            PacketType::B(data) => {
///                match other {
///                    PacketType::A(_) => Ok(MutationResult::Skipped),
///                    PacketType::B(other_data) => data.mutate_crossover_insert(state, other_data, stage_idx),
///                }
///            },
///        }
///    }
/// }
/// ```
/// And now we are able to use the [`PacketCrossoverInsertMutator`].
pub trait HasCrossoverInsertMutation<S>
where
    S: HasRand + HasMaxSize,
{
    /// Perform one crossover mutation where bytes from `other` are inserted into `self`
    ///
    /// The arguments to this function are similar to [`Mutator::mutate()`](libafl::mutators::Mutator::mutate).
    fn mutate_crossover_insert(&mut self, state: &mut S, other: &Self, stage_idx: i32) -> Result<MutationResult, Error>;
}

impl<S> HasCrossoverInsertMutation<S> for BytesInput
where
    S: HasRand + HasMaxSize,
{
    fn mutate_crossover_insert(&mut self, state: &mut S, other: &Self, _stage_idx: i32) -> Result<MutationResult, Error> {
        let self_len = self.len();
        let other_len = other.len();

        if self_len == 0 || other_len == 0 {
            return Ok(MutationResult::Skipped);
        }

        let from = state.rand_mut().below(other_len as u64) as usize;
        let to = state.rand_mut().below(self_len as u64) as usize;
        let len = state.rand_mut().below((other_len - from) as u64) as usize + 1;

        // Make room for `len` additional bytes
        self.bytes_mut().resize(self_len + len, 0);

        // Move bytes at `to` `len` places to the right
        self.bytes_mut().copy_within(to..self_len, to + len);

        // Insert `from` bytes from `other` into self at index `to`
        self.bytes_mut()[to..to + len].copy_from_slice(&other.bytes()[from..from + len]);

        Ok(MutationResult::Mutated)
    }
}

/// Like libafls [`CrossoverInsertMutator`](libafl::mutators::mutations::CrossoverInsertMutator)
/// but for two packets in one seed.
///
/// `P` denotes the type of an individual packet that MUST implement [`HasCrossoverInsertMutation`].
pub struct PacketCrossoverInsertMutator<P, S>
where
    P: HasCrossoverInsertMutation<S> + Clone,
    S: HasRand + HasMaxSize,
{
    phantom: PhantomData<(P, S)>,
}

impl<P, S> PacketCrossoverInsertMutator<P, S>
where
    P: HasCrossoverInsertMutation<S> + Clone,
    S: HasRand + HasMaxSize,
{
    /// Create a new PacketCrossoverInsertMutator
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<I, S, P> Mutator<I, S> for PacketCrossoverInsertMutator<P, S>
where
    P: HasCrossoverInsertMutation<S> + Clone,
    I: Input + HasLen + HasPackets<P>,
    S: HasRand + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut I, stage_idx: i32) -> Result<MutationResult, Error> {
        if input.len() <= 1 {
            return Ok(MutationResult::Skipped);
        }

        let packet = state.rand_mut().below(input.len() as u64) as usize;
        let other = state.rand_mut().below(input.len() as u64) as usize;

        if packet == other {
            return Ok(MutationResult::Skipped);
        }

        let other = input.packets()[other].clone();
        input.packets_mut()[packet].mutate_crossover_insert(state, &other, stage_idx)
    }
}

impl<P, S> Named for PacketCrossoverInsertMutator<P, S>
where
    P: HasCrossoverInsertMutation<S> + Clone,
    S: HasRand + HasMaxSize,
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
    /// Create a new PacketCrossoverReplaceMutator
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

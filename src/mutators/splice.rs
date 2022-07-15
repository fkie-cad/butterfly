use crate::input::HasPackets;
use libafl::{
    bolts::{rands::Rand, tuples::Named, HasLen},
    inputs::{BytesInput, HasBytesVec, Input},
    mutators::{MutationResult, Mutator},
    state::{HasMaxSize, HasRand},
    Error,
};
use std::marker::PhantomData;

/// Signifies that a packet type supports the [`PacketSpliceMutator`] mutator.
///
/// If you want to use the [`PacketSpliceMutator`] your Input type must have a vector
/// of packets that implement this trait.      
/// IMPORTANT: This must be implemented on the packet type, NOT the Input type.
///
/// Already implemented for:
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
/// impl<S> HasSpliceMutation<S> for PacketType
/// where
///    S: HasRand + HasMaxSize,
/// {
///    fn mutate_splice(&mut self, state: &mut S, other: &Self, stage_idx: i32) -> Result<MutationResult, Error> {
///        match self {
///            PacketType::A(data) => {
///                match other {
///                    PacketType::A(other_data) => data.mutate_splice(state, other_data, stage_idx),
///                    PacketType::B(_) => Ok(MutationResult::Skipped),
///                }
///            },
///            PacketType::B(data) => {
///                match other {
///                    PacketType::A(_) => Ok(MutationResult::Skipped),
///                    PacketType::B(other_data) => data.mutate_splice(state, other_data, stage_idx),
///                }
///            },
///        }
///    }
/// }
/// ```
/// And now we are able to use the [`PacketSpliceMutator`].
pub trait HasSpliceMutation<S>
where
    S: HasRand + HasMaxSize,
{
    /// Perform one splicing mutation where `self` and `other` get spliced together at a random midpoint.
    ///
    /// The arguments to this function are similar to [`Mutator::mutate()`](libafl::mutators::Mutator::mutate).
    fn mutate_splice(&mut self, state: &mut S, other: &Self, stage_idx: i32) -> Result<MutationResult, Error>;
}

impl<S> HasSpliceMutation<S> for BytesInput
where
    S: HasRand + HasMaxSize,
{
    fn mutate_splice(&mut self, state: &mut S, other: &Self, _stage_idx: i32) -> Result<MutationResult, Error> {
        let self_len = self.len();
        let other_len = other.len();

        if self_len == 0 || other_len == 0 {
            return Ok(MutationResult::Skipped);
        }

        let to = state.rand_mut().below(self_len as u64) as usize;
        let from = state.rand_mut().below(other_len as u64) as usize;
        let delta = (other_len - from) as i64 - (self_len - to) as i64;

        // Make sure we have enough space for all the bytes from `other`
        if delta > 0 {
            self.bytes_mut().resize(self_len + delta as usize, 0);
        }

        self.bytes_mut()[to..].copy_from_slice(&other.bytes()[from..]);

        Ok(MutationResult::Mutated)
    }
}

/// A mutator that splices two random packets together.
///
/// `P` denotes the type of an individual packet that MUST implement [`HasSpliceMutation`].
/// PacketSpliceMutator respects a lower bound on the number of packets
/// passed as an argument to the constructor.
///
/// # Example
/// ```
/// // Make sure that we always have at least 4 packets
/// let mutator = PacketSpliceMutator::new(4);
/// ```
pub struct PacketSpliceMutator<P, S>
where
    P: HasSpliceMutation<S>,
    S: HasRand + HasMaxSize,
{
    phantom: PhantomData<(P, S)>,
    min_packets: usize,
}

impl<P, S> PacketSpliceMutator<P, S>
where
    P: HasSpliceMutation<S>,
    S: HasRand + HasMaxSize,
{
    /// Create a new PacketSpliceMutator with a lower bound for the number of packets
    pub fn new(min_packets: usize) -> Self {
        Self {
            phantom: PhantomData,
            min_packets: std::cmp::max(1, min_packets),
        }
    }
}

impl<I, P, S> Mutator<I, S> for PacketSpliceMutator<P, S>
where
    P: HasSpliceMutation<S>,
    S: HasRand + HasMaxSize,
    I: Input + HasLen + HasPackets<P>,
{
    fn mutate(&mut self, state: &mut S, input: &mut I, stage_idx: i32) -> Result<MutationResult, Error> {
        if input.len() <= self.min_packets {
            return Ok(MutationResult::Skipped);
        }

        let packet = state.rand_mut().below(input.len() as u64 - 1) as usize;
        let other = input.packets_mut().remove(packet + 1);

        let ret = input.packets_mut()[packet].mutate_splice(state, &other, stage_idx)?;

        if ret == MutationResult::Skipped {
            input.packets_mut().insert(packet + 1, other);
        }

        Ok(ret)
    }
}

impl<P, S> Named for PacketSpliceMutator<P, S>
where
    P: HasSpliceMutation<S>,
    S: HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        "PacketSpliceMutator"
    }
}

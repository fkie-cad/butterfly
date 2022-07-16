use crate::input::HasPackets;
use libafl::{
    bolts::{
        rands::Rand,
        tuples::{tuple_list, Named},
        HasLen,
    },
    inputs::{bytes::BytesInput, Input},
    mutators::{mutations::*, MutationResult, Mutator, MutatorsTuple},
    state::{HasMaxSize, HasRand},
    Error,
};
use std::marker::PhantomData;

/// Tuple of all havoc mutators in libafl that get exactly one input.
///
/// There are also mutators that get two inputs like crossover mutators
/// but these don't work with packet-based inputs so we replace them with
/// our own mutators.
pub type SupportedHavocMutationsType = (
    BitFlipMutator,
    (
        ByteFlipMutator,
        (
            ByteIncMutator,
            (
                ByteDecMutator,
                (
                    ByteNegMutator,
                    (
                        ByteRandMutator,
                        (
                            ByteAddMutator,
                            (
                                WordAddMutator,
                                (
                                    DwordAddMutator,
                                    (
                                        QwordAddMutator,
                                        (
                                            ByteInterestingMutator,
                                            (
                                                WordInterestingMutator,
                                                (
                                                    DwordInterestingMutator,
                                                    (BytesDeleteMutator, (BytesExpandMutator, (BytesInsertMutator, (BytesRandInsertMutator, (BytesSetMutator, (BytesRandSetMutator, (BytesCopyMutator, (BytesInsertCopyMutator, (BytesSwapMutator, ()))))))))),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    ),
);

/// Returns a tuple with all the mutations that can be used by a [`PacketHavocMutator`].
pub fn supported_havoc_mutations() -> SupportedHavocMutationsType {
    tuple_list!(
        BitFlipMutator::new(),
        ByteFlipMutator::new(),
        ByteIncMutator::new(),
        ByteDecMutator::new(),
        ByteNegMutator::new(),
        ByteRandMutator::new(),
        ByteAddMutator::new(),
        WordAddMutator::new(),
        DwordAddMutator::new(),
        QwordAddMutator::new(),
        ByteInterestingMutator::new(),
        WordInterestingMutator::new(),
        DwordInterestingMutator::new(),
        BytesDeleteMutator::new(),
        BytesExpandMutator::new(),
        BytesInsertMutator::new(),
        BytesRandInsertMutator::new(),
        BytesSetMutator::new(),
        BytesRandSetMutator::new(),
        BytesCopyMutator::new(),
        BytesInsertCopyMutator::new(),
        BytesSwapMutator::new()
    )
}

/// Signifies that a packet type supports the [`PacketHavocMutator`].
///
/// If you want to use the [`PacketHavocMutator`] your Input type must have
/// a vector of packets that implement this trait.     
/// IMPORTANT: This must be implemented by the packet type, not the input type.
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
/// impl<MT, S> HasHavocMutation<MT, S> for PacketType
/// where
///    MT: MutatorsTuple<BytesInput, S>,
///    S: HasRand + HasMaxSize,
/// {
///    fn mutate_havoc(&mut self, state: &mut S, mutations: &mut MT, mutation: usize, stage_idx: i32) -> Result<MutationResult, Error> {
///        match self {
///            PacketType::A(data) |
///            PacketType::B(data) => mutations.get_and_mutate(mutation, state, data, stage_idx),
///        }
///    }
/// }
/// ```
/// And now we are able to use the [`PacketHavocMutator`].
pub trait HasHavocMutation<MT, S>
where
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand + HasMaxSize,
{
    /// Perform a single havoc mutation on the current packet
    ///
    /// # Arguments
    /// - `state`: libafls state
    /// - `mutations`: tuple of havoc mutators
    /// - `mutation`: index into the tuple, the mutator to execute
    /// - `stage_idx`: stage index from libafl
    fn mutate_havoc(&mut self, state: &mut S, mutations: &mut MT, mutation: usize, stage_idx: i32) -> Result<MutationResult, Error>;
}

impl<MT, S> HasHavocMutation<MT, S> for BytesInput
where
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand + HasMaxSize,
{
    fn mutate_havoc(&mut self, state: &mut S, mutations: &mut MT, mutation: usize, stage_idx: i32) -> Result<MutationResult, Error> {
        mutations.get_and_mutate(mutation, state, self, stage_idx)
    }
}

/// A mutator that applies a set of havoc mutations to a single packet.
///
/// `P` denotes the packet type that MUST implement [`HasHavocMutation`].
pub struct PacketHavocMutator<I, MT, S, P>
where
    P: HasHavocMutation<MT, S>,
    I: Input + HasLen + HasPackets<P>,
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand + HasMaxSize,
{
    /// These mutation operators must exclusively be for BytesInputs
    mutations: MT,
    phantom: PhantomData<(I, S, P)>,
}

impl<I, MT, S, P> PacketHavocMutator<I, MT, S, P>
where
    P: HasHavocMutation<MT, S>,
    I: Input + HasLen + HasPackets<P>,
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand + HasMaxSize,
{
    /// Create a new PacketHavocMutator with mutators that can be
    /// applied to [`BytesInputs`](libafl::inputs::BytesInput).
    pub fn new(mutations: MT) -> Self {
        Self {
            mutations,
            phantom: PhantomData,
        }
    }

    /// Get the number of stacked mutations to apply
    fn iterations(&self, state: &mut S) -> u64 {
        state.rand_mut().below(16) as u64
    }

    /// Get the next mutation to apply (index into mutation list)
    fn schedule(&self, state: &mut S) -> usize {
        state.rand_mut().below(self.mutations.len() as u64) as usize
    }
}

impl<I, MT, S, P> Mutator<I, S> for PacketHavocMutator<I, MT, S, P>
where
    P: HasHavocMutation<MT, S>,
    I: Input + HasLen + HasPackets<P>,
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut I, stage_idx: i32) -> Result<MutationResult, Error> {
        if input.len() == 0 {
            return Ok(MutationResult::Skipped);
        }

        let mut result = MutationResult::Skipped;
        let iters = self.iterations(state);
        let packet = state.rand_mut().below(input.len() as u64) as usize;

        for _ in 0..iters {
            let mutation = self.schedule(state);

            let outcome = input.packets_mut()[packet].mutate_havoc(state, &mut self.mutations, mutation, stage_idx)?;

            if outcome == MutationResult::Mutated {
                result = MutationResult::Mutated;
            }
        }

        Ok(result)
    }
}

impl<I, MT, S, P> Named for PacketHavocMutator<I, MT, S, P>
where
    P: HasHavocMutation<MT, S>,
    I: Input + HasLen + HasPackets<P>,
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        "PacketHavocMutator"
    }
}

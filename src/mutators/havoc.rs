use libafl::{
    bolts::{
        rands::Rand,
        tuples::{tuple_list, Named},
        HasLen,
    },
    inputs::{bytes::BytesInput, Input},
    mutators::{mutations::*, MutationResult, Mutator, MutatorsTuple},
    state::HasRand,
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

/// Signifies that an input can mutate its packets with havoc mutators.
///
/// This must be implemented by an input if the [`PacketHavocMutator`] is used.
/// See [`mutate_packet()`](crate::HasHavocMutations::mutate_packet()) for more
/// information on how to handle the mutation.
///
/// This trait is necessary because not all packets may be represented as [`BytesInputs`](libafl::inputs::BytesInput).
/// Packets can also be structs or enums and this trait makes it the responsibility of the
/// input - who knows its structure - to execute a mutator selected by the fuzzer.
pub trait HasHavocMutations<MT, S>
where
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand,
{
    /// Given a list of havoc mutators, mutate one packet with them.
    ///
    /// # Arguments
    /// - `packet`: index of the packet that shall be mutated
    /// - `mutations`: [`MutatorsTuple`](libafl::mutators::MutatorsTuple) with mutators that mutate [`BytesInputs`](libafl::inputs::BytesInput)
    /// - `mutation`: An index into the `mutations` tuple selected by the fuzzer.
    ///   This identifies the mutation to perform.
    /// - `state`: libafls state
    /// - `stage_idx`: libafls stage index
    ///
    /// # Example
    /// If a packet only is a [`BytesInput`](libafl::inputs::BytesInput) this function may look like
    /// ```
    /// struct PacketInput {
    ///     packets: Vec<BytesInput>,
    /// }
    /// impl<MT, S> HasHavocMutations<MT, S> for PacketInput
    /// where
    ///     MT: MutatorsTuple<BytesInput, S>,
    ///     S: HasRand,
    /// {
    ///     fn mutate_packet(&mut self, packet: usize, mutations: &mut MT, mutation: usize, state: &mut S, stage_idx: i32) -> Result<MutationResult, Error> {
    ///         mutations.get_and_mutate(mutation, state, &mut self.packets[packet], stage_idx)
    ///     }
    /// }
    /// ```
    fn mutate_packet(&mut self, packet: usize, mutations: &mut MT, mutation: usize, state: &mut S, stage_idx: i32) -> Result<MutationResult, Error>;
}

/// A mutator that applies libafls havoc mutators to a single, random packet.
///
/// Not all of libafls mutators are supported though, see
/// [`supported_havoc_mutations()`](crate::supported_havoc_mutations) for
/// a list of all supported mutators.
///
/// # Example
/// ```
/// let mutator = PacketHavocMutator::new(supported_havoc_mutations());
/// ```
/// or if you want specific mutators
/// ```
/// let mutator = PacketHavocMutator::new(
///     tuple_list!(
///         BitFlipMutator::new(),
///         ByteFlipMutator::new()
///     )
/// );
/// ```
pub struct PacketHavocMutator<I, MT, S>
where
    I: Input + HasLen + HasHavocMutations<MT, S>,
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand,
{
    /// These mutation operators must exclusively be for BytesInputs
    mutations: MT,
    phantom: PhantomData<(S, I)>,
}

impl<I, MT, S> PacketHavocMutator<I, MT, S>
where
    I: Input + HasLen + HasHavocMutations<MT, S>,
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand,
{
    /// Create a new PacketHavocMutator with mutators that can be
    /// applied to [`BytesInputs`](libafl::inputs::BytesInput).
    pub fn new(mutations: MT) -> Self {
        Self {
            mutations,
            phantom: PhantomData,
        }
    }

    /// Get the number of stack mutations to apply
    fn iterations(&self, state: &mut S, _input: &I) -> u64 {
        state.rand_mut().below(16) as u64
    }

    /// Get the next mutation to apply (index into mutation list)
    fn schedule(&self, state: &mut S, _input: &I) -> usize {
        state.rand_mut().below(self.mutations.len() as u64) as usize
    }
}

impl<I, MT, S> Mutator<I, S> for PacketHavocMutator<I, MT, S>
where
    I: Input + HasLen + HasHavocMutations<MT, S>,
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut I, stage_idx: i32) -> Result<MutationResult, Error> {
        if input.len() == 0 {
            return Ok(MutationResult::Skipped);
        }

        let mut result = MutationResult::Skipped;
        let iters = self.iterations(state, input);
        let packet = state.rand_mut().below(input.len() as u64) as usize;

        for _ in 0..iters {
            let mutation = self.schedule(state, input);

            let outcome = input.mutate_packet(packet, &mut self.mutations, mutation, state, stage_idx)?;

            if outcome == MutationResult::Mutated {
                result = MutationResult::Mutated;
            }
        }

        Ok(result)
    }
}

impl<I, MT, S> Named for PacketHavocMutator<I, MT, S>
where
    I: Input + HasLen + HasHavocMutations<MT, S>,
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand,
{
    fn name(&self) -> &str {
        "PacketHavocMutator"
    }
}

use libafl::{
    Error,
    state::HasRand,
    mutators::{
        Mutator,
        MutatorsTuple,
        MutationResult,
        mutations::*,
    },
    inputs::{
        Input,
        bytes::BytesInput,
    },
    bolts::{
        rands::Rand,
        HasLen,
        tuples::{Named, tuple_list},
    },
};
use std::marker::PhantomData;

pub type SupportedHavocMutationsType = (BitFlipMutator, (ByteFlipMutator, (ByteIncMutator, (ByteDecMutator, (ByteNegMutator, (ByteRandMutator, (ByteAddMutator, (WordAddMutator, (DwordAddMutator, (QwordAddMutator, (ByteInterestingMutator, (WordInterestingMutator, (DwordInterestingMutator, (BytesDeleteMutator, (BytesExpandMutator, (BytesInsertMutator, (BytesRandInsertMutator, (BytesSetMutator, (BytesRandSetMutator, (BytesCopyMutator, (BytesInsertCopyMutator, (BytesSwapMutator, () ))))))))))))))))))))));

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

pub trait HasHavocMutations<MT, S>
where
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand,
{
    fn mutate_packet(&mut self, packet: usize, mutations: &mut MT, mutation: usize, state: &mut S, stage_idx: i32) -> Result<MutationResult, Error>;
}

pub struct PacketHavocMutator<I, MT, S>
where
    I: Input + HasLen + HasHavocMutations<MT, S>,
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand,
{
    /// These mutation operators must exclusively be for BytesInputs
    mutations: MT,
    phantom: PhantomData<(S,I)>
}

impl<I, MT, S> PacketHavocMutator<I, MT, S>
where
    I: Input + HasLen + HasHavocMutations<MT, S>,
    MT: MutatorsTuple<BytesInput, S>,
    S: HasRand,
{
    pub fn new(mutations: MT) -> Self {
        Self {
            mutations,
            phantom: PhantomData
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
            
            let outcome = input.mutate_packet(
                packet,
                &mut self.mutations,
                mutation,
                state,
                stage_idx
            )?;
            
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

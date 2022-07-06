use libafl::{
    Error,
    inputs::Input,
    mutators::{MutatorsTuple, ComposedByMutations, ScheduledMutator, MutationResult, Mutator},
    state::HasRand,
    bolts::rands::Rand,
};
use std::marker::PhantomData;

pub struct PacketMutationScheduler<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    mutations: MT,
    phantom: PhantomData<(I, S)>,
}

impl<I, MT, S> PacketMutationScheduler<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    pub fn new(mutations: MT) -> Self {
        Self {
            mutations,
            phantom: PhantomData,
        }
    }
}

impl<I, MT, S> ComposedByMutations<I, MT, S> for PacketMutationScheduler<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn mutations(&self) -> &MT {
        &self.mutations
    }
    
    fn mutations_mut(&mut self) -> &mut MT {
        &mut self.mutations
    }
}

impl<I, MT, S> Mutator<I, S> for PacketMutationScheduler<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut I, stage_idx: i32) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input, stage_idx)
    }
}

impl<I, MT, S> ScheduledMutator<I, MT, S> for PacketMutationScheduler<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn iterations(&self, _state: &mut S, _input: &I) -> u64 {
        1
    }
    
    fn schedule(&self, state: &mut S, _input: &I) -> usize {
        state.rand_mut().below(self.mutations.len() as u64) as usize
    }
    
    fn scheduled_mutate(&mut self, state: &mut S, input: &mut I, stage_idx: i32) -> Result<MutationResult, Error> {
        let mut result = MutationResult::Skipped;
        
        while result == MutationResult::Skipped {
            let mutation = self.schedule(state, input);
            result = self.mutations.get_and_mutate(mutation, state, input, stage_idx)?;
        }
        
        Ok(result)
    }
}
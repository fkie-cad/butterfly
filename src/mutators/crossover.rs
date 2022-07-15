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

/// Signifies that a packet type supports the [`PacketCrossoverReplaceMutator`] mutator.    
///
/// If you want to use the [`PacketCrossoverReplaceMutator`] your Input type must have
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
/// impl<S> HasCrossoverReplaceMutation<S> for PacketType
/// where
///    S: HasRand + HasMaxSize,
/// {
///    fn mutate_crossover_replace(&mut self, state: &mut S, other: &Self, stage_idx: i32) -> Result<MutationResult, Error> {
///        match self {
///            PacketType::A(data) => {
///                match other {
///                    PacketType::A(other_data) => data.mutate_crossover_replace(state, other_data, stage_idx),
///                    PacketType::B(_) => Ok(MutationResult::Skipped),
///                }
///            },
///            PacketType::B(data) => {
///                match other {
///                    PacketType::A(_) => Ok(MutationResult::Skipped),
///                    PacketType::B(other_data) => data.mutate_crossover_replace(state, other_data, stage_idx),
///                }
///            },
///        }
///    }
/// }
/// ```
/// And now we are able to use the [`PacketCrossoverReplaceMutator`].
pub trait HasCrossoverReplaceMutation<S>
where
    S: HasRand + HasMaxSize,
{
    /// Perform one crossover mutation where bytes in `self` are replaced by bytes from `other`.
    ///
    /// The arguments to this function are similar to [`Mutator::mutate()`](libafl::mutators::Mutator::mutate).
    fn mutate_crossover_replace(&mut self, state: &mut S, other: &Self, stage_idx: i32) -> Result<MutationResult, Error>;
}

impl<S> HasCrossoverReplaceMutation<S> for BytesInput
where
    S: HasRand + HasMaxSize,
{
    fn mutate_crossover_replace(&mut self, state: &mut S, other: &Self, _stage_idx: i32) -> Result<MutationResult, Error> {
        let self_len = self.len();
        let other_len = other.len();

        if self_len == 0 || other_len == 0 {
            return Ok(MutationResult::Skipped);
        }

        let from = state.rand_mut().below(other_len as u64) as usize;
        let to = state.rand_mut().below(self_len as u64) as usize;
        let len = 1 + state.rand_mut().below(std::cmp::min(other_len - from, self_len - to) as u64) as usize;

        self.bytes_mut()[to..to + len].copy_from_slice(&other.bytes()[from..from + len]);

        Ok(MutationResult::Mutated)
    }
}

/// Like libafls [`CrossoverReplaceMutator`](libafl::mutators::mutations::CrossoverReplaceMutator)
/// but for two packets in one seed.
///
/// `P` denotes the type of an individual packet that MUST implement [`HasCrossoverReplaceMutation`].
pub struct PacketCrossoverReplaceMutator<P, S>
where
    P: HasCrossoverReplaceMutation<S> + Clone,
    S: HasRand + HasMaxSize,
{
    phantom: PhantomData<(P, S)>,
}

impl<P, S> PacketCrossoverReplaceMutator<P, S>
where
    P: HasCrossoverReplaceMutation<S> + Clone,
    S: HasRand + HasMaxSize,
{
    /// Create a new PacketCrossoverReplaceMutator
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<I, S, P> Mutator<I, S> for PacketCrossoverReplaceMutator<P, S>
where
    P: HasCrossoverReplaceMutation<S> + Clone,
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
        input.packets_mut()[packet].mutate_crossover_replace(state, &other, stage_idx)
    }
}

impl<P, S> Named for PacketCrossoverReplaceMutator<P, S>
where
    P: HasCrossoverReplaceMutation<S> + Clone,
    S: HasRand + HasMaxSize,
{
    fn name(&self) -> &str {
        "PacketCrossoverReplaceMutator"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libafl::{
        bolts::rands::StdRand,
        inputs::BytesInput,
        mutators::MutationResult,
        state::{HasMaxSize, HasRand},
    };

    struct TestState {
        rand: StdRand,
        max_size: usize,
    }
    impl TestState {
        fn new() -> Self {
            Self {
                rand: StdRand::with_seed(0),
                max_size: 0,
            }
        }
    }
    impl HasRand for TestState {
        type Rand = StdRand;

        fn rand(&self) -> &StdRand {
            &self.rand
        }

        fn rand_mut(&mut self) -> &mut StdRand {
            &mut self.rand
        }
    }
    impl HasMaxSize for TestState {
        fn max_size(&self) -> usize {
            self.max_size
        }

        fn set_max_size(&mut self, max_size: usize) {
            self.max_size = max_size;
        }
    }

    #[test]
    fn test_insert_empty() {
        let mut state = TestState::new();
        let mut a = BytesInput::new(Vec::new());
        let b = BytesInput::new(Vec::new());

        for _ in 0..100 {
            assert_eq!(a.mutate_crossover_insert(&mut state, &b, 0).unwrap(), MutationResult::Skipped);
        }
    }

    #[test]
    fn test_insert_len1() {
        let mut state = TestState::new();
        let b = BytesInput::new(b"B".to_vec());

        for _ in 0..100 {
            let mut a = BytesInput::new(b"A".to_vec());
            assert_eq!(a.mutate_crossover_insert(&mut state, &b, 0).unwrap(), MutationResult::Mutated);
            assert!(a.bytes() == b"AB" || a.bytes() == b"BA");
        }
    }

    #[test]
    fn test_insert_resize() {
        let mut state = TestState::new();
        let mut a = BytesInput::new(b"A".to_vec());
        let b = BytesInput::new(b"asdasd fasd fa sdf asdf asdfasfd asdfsadf asdfsadf asdfsa df ".to_vec());

        for _ in 0..100 {
            assert_eq!(a.mutate_crossover_insert(&mut state, &b, 0).unwrap(), MutationResult::Mutated);
        }
    }

    #[test]
    fn test_replace_empty() {
        let mut state = TestState::new();
        let mut a = BytesInput::new(Vec::new());
        let b = BytesInput::new(Vec::new());

        for _ in 0..100 {
            assert_eq!(a.mutate_crossover_replace(&mut state, &b, 0).unwrap(), MutationResult::Skipped);
        }
    }

    #[test]
    fn test_replace_len1() {
        let mut state = TestState::new();
        let mut a = BytesInput::new(b"A".to_vec());
        let b = BytesInput::new(b"B".to_vec());

        for _ in 0..100 {
            assert_eq!(a.mutate_crossover_replace(&mut state, &b, 0).unwrap(), MutationResult::Mutated);
            assert_eq!(a.bytes(), b"B");
        }
    }

    #[test]
    fn test_replace_resize() {
        let mut state = TestState::new();
        let mut a = BytesInput::new(b"A".to_vec());
        let b = BytesInput::new(b"asdasd fasd fa sdf asdf asdfasfd asdfsadf asdfsadf asdfsa df ".to_vec());

        for _ in 0..100 {
            assert_eq!(a.mutate_crossover_replace(&mut state, &b, 0).unwrap(), MutationResult::Mutated);
        }
    }
}

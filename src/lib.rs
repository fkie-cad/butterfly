//! butterfly provides LibAFL components for stateful fuzzing
//!
//! # Overview
//! butterfly offers
//! 1. A new representation of inputs as sequences of packets
//!    that can be loaded from pcap files. The packets can be of any type.
//! 2. Packet-aware mutators that mutate only one packet and leave
//!    all others intact to reach deeper program states
//! 3. Protocol-aware mutators that can reorder, duplicate, splice and delete packets
//!    in addition to "normal" mutations
//! 4. An observer that tracks which states the target goes through as it processes the packets.    
//!    This is used to build a state-graph of the target and identify
//!    when new states have been reached.
//!
//! # Components
//! - **Input**   
//!   - In order to create a new, working input type you MUST implement the following traits:       
//!   [`Hash`](core::hash::Hash), [`Debug`](core::fmt::Debug), [`Clone`](core::clone::Clone), [`Serialize`](serde::Serialize), [`Deserialize`](serde::Deserialize), [`Input`](libafl::inputs::Input)     
//!   - To make it usable by other butterfly components, implement [`HasPackets`], [`HasLen`](libafl::bolts::HasLen)
//!   - If you want to load it from a PCAP file, implement [`HasPcapRepresentation`]
//! - **Mutators**
//!   - havoc: [`PacketHavocMutator`] gets a list of havoc mutators and uses [`HasHavocMutation`] to mutate a selected packet.      
//!     Not all of libafls havoc mutators work with packet-based inputs, though. [`supported_havoc_mutations`] gives you all havoc
//!     mutators that work
//!   - packet-mutators:
//!     - [`PacketDeleteMutator`], [`PacketDuplicateMutator`], [`PacketReorderMutator`]
//!   - crossover mutators:
//!     - [`PacketCrossoverInsertMutator`] and [`PacketCrossoverReplaceMutator`]
//!   - splicing mutators:
//!     - [`PacketSpliceMutator`]
//! - **Observer**
//!   - [`StateObserver`] builds a state-graph
//!   - The executor is responsible for calling [`StateObserver::record()`] with state information inferred from
//!     the fuzz target
//! - **Feedback**
//!   - [`StateFeedback`] determines if a [`StateObserver`] has seen new states in the last run
//! - **Monitor**
//!   - butterfly provides a [`StateMonitor`] that prints information about the state-graph in addition to
//!     all the other info
//!   - if you want to use a different monitor but still want to get state-graph information you can
//!     implement [`HasStateStats`]
//!
//! # Features
//! - `graphviz`
//!   - Adds [`GraphvizMonitor`] that writes a DOT representation of the state graph to a file
//!
//! # Tutorials, examples and more...
//! ... can be found in our [repository](https://github.com/fkie-cad/butterfly) and [wiki](https://github.com/fkie-cad/butterfly/wiki).

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![allow(clippy::new_without_default)]
#![feature(test)]
#![forbid(unsafe_code)]

mod event;
mod feedback;
mod input;
mod monitor;
mod mutators;
mod observer;
mod scheduler;

pub use event::{USER_STAT_EDGES, USER_STAT_NODES};
pub use feedback::StateFeedback;
pub use input::{load_pcaps, HasPackets, HasPcapRepresentation};
pub use monitor::{HasStateStats, StateMonitor};
pub use mutators::{
    supported_havoc_mutations, HasCrossoverInsertMutation, HasCrossoverReplaceMutation, HasHavocMutation, HasSpliceMutation, PacketCrossoverInsertMutator, PacketCrossoverReplaceMutator, PacketDeleteMutator, PacketDuplicateMutator, PacketHavocMutator,
    PacketReorderMutator, PacketSpliceMutator, SupportedHavocMutationsType,
};
pub use observer::StateObserver;
pub use scheduler::PacketMutationScheduler;

#[cfg(feature = "graphviz")]
pub use {
    monitor::GraphvizMonitor,
    event::USER_STAT_STATEGRAPH,
};

/// The tests below are just for checking that harnesses compile
/// with the butterfly components. We don't actually want to execute
/// any harness.
#[cfg(test)]
mod tests {
    use super::*;
    use libafl::{
        bolts::{
            core_affinity::Cores,
            launcher::Launcher,
            rands::StdRand,
            shmem::{ShMemProvider, StdShMemProvider},
            tuples::tuple_list,
            HasLen,
        },
        corpus::InMemoryCorpus,
        events::{EventConfig, SimpleEventManager},
        executors::{Executor, ExitKind, HasObservers},
        feedbacks::CrashFeedback,
        inputs::{BytesInput, Input},
        mutators::{MutationResult, MutatorsTuple},
        observers::ObserversTuple,
        schedulers::queue::QueueScheduler,
        stages::StdMutationalStage,
        state::{HasMaxSize, HasRand, StdState},
        Error, Fuzzer, StdFuzzer,
    };
    use pcap::{Capture, Offline};
    use serde::{Deserialize, Serialize};
    use std::fmt::{Debug, Formatter};
    use std::marker::PhantomData;

    #[derive(Hash, Debug, Clone, Serialize, Deserialize)]
    enum PacketType {
        A(BytesInput),
        B(BytesInput),
    }

    impl<S> HasCrossoverInsertMutation<S> for PacketType
    where
        S: HasRand + HasMaxSize,
    {
        fn mutate_crossover_insert(&mut self, state: &mut S, other: &Self, stage_idx: i32) -> Result<MutationResult, Error> {
            match self {
                PacketType::A(data) => match other {
                    PacketType::A(other_data) => data.mutate_crossover_insert(state, other_data, stage_idx),
                    PacketType::B(_) => Ok(MutationResult::Skipped),
                },
                PacketType::B(data) => match other {
                    PacketType::A(_) => Ok(MutationResult::Skipped),
                    PacketType::B(other_data) => data.mutate_crossover_insert(state, other_data, stage_idx),
                },
            }
        }
    }

    impl<S> HasCrossoverReplaceMutation<S> for PacketType
    where
        S: HasRand + HasMaxSize,
    {
        fn mutate_crossover_replace(&mut self, state: &mut S, other: &Self, stage_idx: i32) -> Result<MutationResult, Error> {
            match self {
                PacketType::A(data) => match other {
                    PacketType::A(other_data) => data.mutate_crossover_replace(state, other_data, stage_idx),
                    PacketType::B(_) => Ok(MutationResult::Skipped),
                },
                PacketType::B(data) => match other {
                    PacketType::A(_) => Ok(MutationResult::Skipped),
                    PacketType::B(other_data) => data.mutate_crossover_replace(state, other_data, stage_idx),
                },
            }
        }
    }

    impl<S> HasSpliceMutation<S> for PacketType
    where
        S: HasRand + HasMaxSize,
    {
        fn mutate_splice(&mut self, state: &mut S, other: &Self, stage_idx: i32) -> Result<MutationResult, Error> {
            match self {
                PacketType::A(data) => match other {
                    PacketType::A(other_data) => data.mutate_splice(state, other_data, stage_idx),
                    PacketType::B(_) => Ok(MutationResult::Skipped),
                },
                PacketType::B(data) => match other {
                    PacketType::A(_) => Ok(MutationResult::Skipped),
                    PacketType::B(other_data) => data.mutate_splice(state, other_data, stage_idx),
                },
            }
        }
    }

    impl<MT, S> HasHavocMutation<MT, S> for PacketType
    where
        MT: MutatorsTuple<BytesInput, S>,
        S: HasRand + HasMaxSize,
    {
        fn mutate_havoc(&mut self, state: &mut S, mutations: &mut MT, mutation: usize, stage_idx: i32) -> Result<MutationResult, Error> {
            match self {
                PacketType::A(data) | PacketType::B(data) => mutations.get_and_mutate(mutation, state, data, stage_idx),
            }
        }
    }

    #[derive(Hash, Debug, Clone, Serialize, Deserialize)]
    struct PacketInput {
        packets: Vec<PacketType>,
    }
    impl Input for PacketInput {
        fn generate_name(&self, _idx: usize) -> String {
            todo!();
        }
    }
    impl HasPackets<PacketType> for PacketInput {
        fn packets(&self) -> &[PacketType] {
            &self.packets
        }

        fn packets_mut(&mut self) -> &mut Vec<PacketType> {
            &mut self.packets
        }
    }
    impl HasLen for PacketInput {
        fn len(&self) -> usize {
            self.packets.len()
        }
    }
    impl HasPcapRepresentation<PacketInput> for PacketInput {
        fn from_pcap(mut _capture: Capture<Offline>) -> Result<Self, Error> {
            todo!();
        }
    }

    type TargetState = [u8; 8];

    struct ExampleExecutor<OT, S>
    where
        OT: ObserversTuple<PacketInput, S>,
    {
        observers: OT,
        phantom: PhantomData<S>,
    }
    impl<OT, S> ExampleExecutor<OT, S>
    where
        OT: ObserversTuple<PacketInput, S>,
    {
        fn new(observers: OT) -> Self {
            Self {
                observers,
                phantom: PhantomData,
            }
        }
    }
    impl<OT, S> Debug for ExampleExecutor<OT, S>
    where
        OT: ObserversTuple<PacketInput, S>,
    {
        fn fmt(&self, _f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
            todo!();
        }
    }
    impl<OT, S, EM, Z> Executor<EM, PacketInput, S, Z> for ExampleExecutor<OT, S>
    where
        OT: ObserversTuple<PacketInput, S>,
    {
        fn run_target(&mut self, _fuzzer: &mut Z, _state: &mut S, _mgr: &mut EM, input: &PacketInput) -> Result<ExitKind, Error> {
            let state_observer: &mut StateObserver<TargetState> = self.observers.match_name_mut("state").unwrap();

            for _packet in &input.packets {
                // do some I/O with packet data

                // the executor is responsible for getting state information
                // from the target
                let current_state = TargetState::default();

                state_observer.record(&current_state);
            }

            Ok(ExitKind::Ok)
        }
    }
    impl<OT, S> HasObservers<PacketInput, OT, S> for ExampleExecutor<OT, S>
    where
        OT: ObserversTuple<PacketInput, S>,
    {
        fn observers(&self) -> &OT {
            &self.observers
        }

        fn observers_mut(&mut self) -> &mut OT {
            &mut self.observers
        }
    }

    #[allow(dead_code)]
    fn multicore_harness() {
        let shmem_provider = StdShMemProvider::new().unwrap();
        let mon = StateMonitor::new();

        let mut run_client = |_state: Option<_>, mut mgr, _core_id| {
            let state_observer = StateObserver::<TargetState>::new("state");
            let mut feedback = StateFeedback::new(&state_observer);
            let mut objective = CrashFeedback::new();
            let mut state = StdState::new(StdRand::with_seed(0), InMemoryCorpus::new(), InMemoryCorpus::new(), &mut feedback, &mut objective).unwrap();
            let scheduler = QueueScheduler::new();
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
            let mutator = PacketMutationScheduler::new(tuple_list!(
                PacketHavocMutator::new(supported_havoc_mutations()),
                PacketReorderMutator::new(),
                PacketSpliceMutator::new(4),
                PacketCrossoverInsertMutator::new(),
                PacketCrossoverReplaceMutator::new(),
                PacketDeleteMutator::new(4),
                PacketDuplicateMutator::new(16)
            ));
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));
            let mut executor = ExampleExecutor::new(tuple_list!(state_observer));

            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
            Ok(())
        };

        let cores = Cores::from_cmdline("all").unwrap();
        let mut launcher = Launcher::builder().shmem_provider(shmem_provider).configuration(EventConfig::from_name("default")).monitor(mon).run_client(&mut run_client).cores(&cores).build();

        launcher.launch().unwrap();
    }

    #[allow(dead_code)]
    fn singlecore_harness() {
        let mon = StateMonitor::new();
        let mut mgr = SimpleEventManager::new(mon);
        let state_observer = StateObserver::<TargetState>::new("state");
        let mut feedback = StateFeedback::new(&state_observer);
        let mut objective = CrashFeedback::new();
        let mut state = StdState::new(StdRand::with_seed(0), InMemoryCorpus::new(), InMemoryCorpus::new(), &mut feedback, &mut objective).unwrap();
        let scheduler = QueueScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
        let mutator = PacketMutationScheduler::new(tuple_list!(
            PacketHavocMutator::new(supported_havoc_mutations()),
            PacketReorderMutator::new(),
            PacketSpliceMutator::new(4),
            PacketCrossoverInsertMutator::new(),
            PacketCrossoverReplaceMutator::new(),
            PacketDeleteMutator::new(4),
            PacketDuplicateMutator::new(16)
        ));
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));
        let mut executor = ExampleExecutor::new(tuple_list!(state_observer));
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).unwrap();
    }

    #[derive(Hash, Debug, Clone, Serialize, Deserialize)]
    struct RawInput {
        packets: Vec<BytesInput>,
    }
    impl Input for RawInput {
        fn generate_name(&self, _idx: usize) -> String {
            todo!();
        }
    }
    impl HasPackets<BytesInput> for RawInput {
        fn packets(&self) -> &[BytesInput] {
            &self.packets
        }

        fn packets_mut(&mut self) -> &mut Vec<BytesInput> {
            &mut self.packets
        }
    }
    impl HasLen for RawInput {
        fn len(&self) -> usize {
            self.packets.len()
        }
    }
    impl HasPcapRepresentation<RawInput> for RawInput {
        fn from_pcap(mut _capture: Capture<Offline>) -> Result<Self, Error> {
            todo!();
        }
    }

    struct RawExecutor<OT, S>
    where
        OT: ObserversTuple<RawInput, S>,
    {
        observers: OT,
        phantom: PhantomData<S>,
    }
    impl<OT, S> RawExecutor<OT, S>
    where
        OT: ObserversTuple<RawInput, S>,
    {
        fn new(observers: OT) -> Self {
            Self {
                observers,
                phantom: PhantomData,
            }
        }
    }
    impl<OT, S> Debug for RawExecutor<OT, S>
    where
        OT: ObserversTuple<RawInput, S>,
    {
        fn fmt(&self, _f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
            todo!();
        }
    }
    impl<OT, S, EM, Z> Executor<EM, RawInput, S, Z> for RawExecutor<OT, S>
    where
        OT: ObserversTuple<RawInput, S>,
    {
        fn run_target(&mut self, _fuzzer: &mut Z, _state: &mut S, _mgr: &mut EM, input: &RawInput) -> Result<ExitKind, Error> {
            let state_observer: &mut StateObserver<TargetState> = self.observers.match_name_mut("state").unwrap();

            for _packet in &input.packets {
                // do some I/O with packet data

                // the executor is responsible for getting state information
                // from the target
                let current_state = TargetState::default();

                state_observer.record(&current_state);
            }

            Ok(ExitKind::Ok)
        }
    }
    impl<OT, S> HasObservers<RawInput, OT, S> for RawExecutor<OT, S>
    where
        OT: ObserversTuple<RawInput, S>,
    {
        fn observers(&self) -> &OT {
            &self.observers
        }

        fn observers_mut(&mut self) -> &mut OT {
            &mut self.observers
        }
    }

    #[allow(dead_code)]
    fn raw_harness() {
        let mon = StateMonitor::new();
        let mut mgr = SimpleEventManager::new(mon);
        let state_observer = StateObserver::<TargetState>::new("state");
        let mut feedback = StateFeedback::new(&state_observer);
        let mut objective = CrashFeedback::new();
        let mut state = StdState::new(StdRand::with_seed(0), InMemoryCorpus::new(), InMemoryCorpus::new(), &mut feedback, &mut objective).unwrap();
        let scheduler = QueueScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
        let mutator = PacketMutationScheduler::new(tuple_list!(
            PacketHavocMutator::new(supported_havoc_mutations()),
            PacketReorderMutator::new(),
            PacketSpliceMutator::new(4),
            PacketCrossoverInsertMutator::new(),
            PacketCrossoverReplaceMutator::new(),
            PacketDeleteMutator::new(4),
            PacketDuplicateMutator::new(16)
        ));
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));
        let mut executor = RawExecutor::new(tuple_list!(state_observer));
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).unwrap();
    }
}

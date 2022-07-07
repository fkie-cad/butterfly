//! butterfly provides LibAFL components for stateful fuzzing
//!
//! # Overview
//! butterfly offers
//! 1. A new representation of inputs as sequences of packets
//!    that can be loaded from pcap files
//! 2. Packet-aware mutators that mutate only one packet and leave
//!    all others intact to reach deeper program states
//! 3. Protocol-aware mutators that can reorder, duplicate, splice and delete packets
//!    in addition to "normal" havoc mutations 
//! 4. An observer that tracks which states the target goes through as it processes the packets.    
//!    This is used to build a state-graph of the target and identify
//!    when new states have been reached.
//!
//! # Components
//! - **Input**   
//!   - In order to create a new, working input type you MUST implement the following traits:       
//!   [`Hash`](core::hash::Hash), [`Debug`](core::fmt::Debug), [`Clone`](core::clone::Clone), [`Serialize`](serde::Serialize), [`Deserialize`](serde::Deserialize), [`Input`](libafl::inputs::Input)     
//!   - To make it usable by other butterfly components, implement [`HasPackets`], [`HasLen`](libafl::bolts::HasLen)
//!   - If you want to use havoc mutations, implement [`HasHavocMutations`]
//!   - If you want to load it from a PCAP file, implement [`HasPcapRepresentation`]
//! - **Mutators**
//!   - havoc: [`PacketHavocMutator`] gets a list of havoc mutators and uses [`HasHavocMutations`] to mutate a selected packet.      
//!     Not all of libafls havoc mutators work with packet-based inputs, though. [`supported_havoc_mutations`] gives you all havoc
//!     mutators that work
//!   - packet-mutators:
//!     - [`PacketDeleteMutator`], [`PacketDuplicateMutator`], [`PacketReorderMutator`] work with all input types
//!     - the rest only works with inputs whose packets implement [`HasBytesVec`](libafl::inputs::HasBytesVec)
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
//! # Tutorials, examples and more...
//! ... can be found in our [repository](https://github.com/fkie-cad/butterfly) and [wiki](https://github.com/fkie-cad/butterfly/wiki).

#![deny(missing_docs)]
#![allow(clippy::new_without_default)]

mod feedback;
mod input;
mod monitor;
mod mutators;
mod observer;
mod event;
mod scheduler;

pub use feedback::StateFeedback;
pub use input::{HasPackets, HasPcapRepresentation, load_pcaps};
pub use monitor::{StateMonitor, HasStateStats, FuzzerStatsWrapper};
pub use mutators::{
    supported_havoc_mutations,
    SupportedHavocMutationsType,
    HasHavocMutations,
    PacketHavocMutator,
    PacketSpliceMutator,
    PacketReorderMutator,
    PacketCrossoverInsertMutator,
    PacketCrossoverReplaceMutator,
    PacketDeleteMutator,
    PacketDuplicateMutator,
};
pub use observer::StateObserver;
pub use event::{USER_STAT_NODES, USER_STAT_EDGES};
pub use scheduler::PacketMutationScheduler;

/// The tests below are just for checking that harnesses compile
/// with the butterfly components. We don't actually want to execute
/// any harness.
#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Serialize, Deserialize};
    use libafl::{
        Error, StdFuzzer, Fuzzer,
        inputs::{Input, BytesInput},
        mutators::{
            MutatorsTuple,
            MutationResult,
        },
        state::{HasRand, StdState},
        bolts::{
            HasLen,
            shmem::{StdShMemProvider, ShMemProvider},
            rands::StdRand,
            tuples::tuple_list,
            core_affinity::Cores,
            launcher::Launcher,
        },
        observers::ObserversTuple,
        executors::{Executor, ExitKind, HasObservers},
        corpus::InMemoryCorpus,
        feedbacks::CrashFeedback,
        schedulers::queue::QueueScheduler,
        events::{EventConfig, SimpleEventManager},
        stages::StdMutationalStage,
    };
    use pcap::{Capture, Offline};
    use std::marker::PhantomData;
    use std::fmt::{Debug, Formatter};
    
    #[derive(Hash, Debug, Clone, Serialize, Deserialize)]
    struct PacketInput {
        packets: Vec<BytesInput>,
    }
    impl<MT, S> HasHavocMutations<MT, S> for PacketInput
    where
        MT: MutatorsTuple<BytesInput, S>,
        S: HasRand,
    {
        fn mutate_packet(&mut self, packet: usize, mutations: &mut MT, mutation: usize, state: &mut S, stage_idx: i32) -> Result<MutationResult, Error> {
            mutations.get_and_mutate(mutation, state, &mut self.packets[packet], stage_idx)
        }
    }
    impl Input for PacketInput {
        fn generate_name(&self, _idx: usize) -> String {
            todo!();
        }
    }
    impl HasPackets<BytesInput> for PacketInput {
        fn packets(&self) -> &[BytesInput] {
            &self.packets
        }
        
        fn packets_mut(&mut self) -> &mut Vec<BytesInput> {
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
    
    #[test]
    #[ignore]
    fn multicore_harness() {
        let shmem_provider = StdShMemProvider::new().unwrap();
        let mon = FuzzerStatsWrapper::new(StateMonitor::new(), "fuzzer_stats", 30);
        
        let mut run_client = |_state: Option<_>, mut mgr, _core_id| {
            let state_observer = StateObserver::<TargetState>::new("state");
            let mut feedback = StateFeedback::new(&state_observer);
            let mut objective = CrashFeedback::new();
            let mut state = StdState::new(
                StdRand::with_seed(0),
                InMemoryCorpus::new(),
                InMemoryCorpus::new(),
                &mut feedback,
                &mut objective,
            ).unwrap();
            let scheduler = QueueScheduler::new();
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
            let mutator = PacketMutationScheduler::new(
                tuple_list!(
                    PacketHavocMutator::new(supported_havoc_mutations()),
                    PacketReorderMutator::new(),
                    PacketSpliceMutator::new(4),
                    PacketCrossoverInsertMutator::new(),
                    PacketCrossoverReplaceMutator::new(),
                    PacketDeleteMutator::new(4),
                    PacketDuplicateMutator::new(16)
                )
            );
            let mut stages = tuple_list!(
                StdMutationalStage::new(mutator)
            );
            let mut executor = ExampleExecutor::new(
                tuple_list!(
                    state_observer
                )
            );
            
            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
            Ok(())
        };
        
        let cores = Cores::from_cmdline("all").unwrap();
        let mut launcher = Launcher::builder()
            .shmem_provider(shmem_provider)
            .configuration(EventConfig::from_name("default"))
            .monitor(mon)
            .run_client(&mut run_client)
            .cores(&cores)
            .build();
        
        launcher.launch().unwrap();
    }
    
    #[test]
    #[ignore]
    fn singlecore_harness() {
        let mon = FuzzerStatsWrapper::new(StateMonitor::new(), "fuzzer_stats", 30);
        let mut mgr = SimpleEventManager::new(mon);
        let state_observer = StateObserver::<TargetState>::new("state");
        let mut feedback = StateFeedback::new(&state_observer);
        let mut objective = CrashFeedback::new();
        let mut state = StdState::new(
            StdRand::with_seed(0),
            InMemoryCorpus::new(),
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        ).unwrap();
        let scheduler = QueueScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
        let mutator = PacketMutationScheduler::new(
            tuple_list!(
                PacketHavocMutator::new(supported_havoc_mutations()),
                PacketReorderMutator::new(),
                PacketSpliceMutator::new(4),
                PacketCrossoverInsertMutator::new(),
                PacketCrossoverReplaceMutator::new(),
                PacketDeleteMutator::new(4),
                PacketDuplicateMutator::new(16)
            )
        );
        let mut stages = tuple_list!(
            StdMutationalStage::new(mutator)
        );
        let mut executor = ExampleExecutor::new(
            tuple_list!(
                state_observer
            )
        );
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr).unwrap();
    }
}

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

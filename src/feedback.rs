use crate::{
    event::{USER_STAT_EDGES, USER_STAT_NODES},
    observer::StateObserver,
};
use libafl::{
    bolts::tuples::Named,
    events::{Event, EventFirer},
    executors::ExitKind,
    feedbacks::{Feedback, HasObserverName},
    inputs::Input,
    monitors::UserStats,
    observers::ObserversTuple,
    state::HasClientPerfMonitor,
    Error,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ord;
use std::fmt::Debug;
use std::marker::PhantomData;

/// Determines that an input is interesting if it led to new states or transitions in the previous run.
#[derive(Debug)]
pub struct StateFeedback<PS>
where
    PS: Debug + Clone + Ord + Serialize + for<'a> Deserialize<'a>,
{
    observer_name: String,
    phantom: PhantomData<PS>,
}

impl<PS> StateFeedback<PS>
where
    PS: Debug + Clone + Ord + Serialize + for<'a> Deserialize<'a>,
{
    /// Create a new StateFeedback from a StateObserver
    pub fn new(observer: &StateObserver<PS>) -> Self {
        Self {
            observer_name: observer.name().to_string(),
            phantom: PhantomData,
        }
    }
}

impl<PS> Named for StateFeedback<PS>
where
    PS: Debug + Clone + Ord + Serialize + for<'a> Deserialize<'a>,
{
    fn name(&self) -> &str {
        "StateFeedback"
    }
}

impl<PS> HasObserverName for StateFeedback<PS>
where
    PS: Debug + Clone + Ord + Serialize + for<'a> Deserialize<'a>,
{
    fn observer_name(&self) -> &str {
        &self.observer_name
    }
}

impl<I, S, PS> Feedback<I, S> for StateFeedback<PS>
where
    I: Input,
    S: HasClientPerfMonitor,
    PS: Debug + Clone + Ord + Serialize + for<'a> Deserialize<'a>,
{
    fn is_interesting<EM, OT>(&mut self, state: &mut S, mgr: &mut EM, _input: &I, observers: &OT, _exit_kind: &ExitKind) -> Result<bool, Error>
    where
        EM: EventFirer<I>,
        OT: ObserversTuple<I, S>,
    {
        let state_observer = observers.match_name::<StateObserver<PS>>(&self.observer_name).unwrap();

        let ret = state_observer.had_new_transitions();

        if ret {
            let (nodes, edges) = state_observer.info();

            mgr.fire(
                state,
                Event::UpdateUserStats {
                    name: USER_STAT_NODES.to_string(),
                    value: UserStats::Number(nodes as u64),
                    phantom: PhantomData,
                },
            )?;
            mgr.fire(
                state,
                Event::UpdateUserStats {
                    name: USER_STAT_EDGES.to_string(),
                    value: UserStats::Number(edges as u64),
                    phantom: PhantomData,
                },
            )?;
        }

        Ok(ret)
    }
}

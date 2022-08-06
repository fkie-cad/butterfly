use crate::event::{USER_STAT_EDGES, USER_STAT_NODES};
use libafl::{
    bolts::{current_time, format_duration_hms},
    monitors::{ClientStats, Monitor, UserStats},
};
use std::time::Duration;

#[cfg(feature = "graphviz")]
use {crate::event::USER_STAT_STATEGRAPH, std::fs::File, std::io::Write, std::path::PathBuf};

/// Adds capabilities to a Monitor to get information about the state-graph.
///
/// All functions are already provided.   
/// You just need to do
/// ```
/// impl HasStateStats for YourMonitor {}
/// ```
/// and then you can invoke the given functions in `YourMonitor::display()`.
pub trait HasStateStats: Monitor {
    /// Helper function used by the other functions.
    fn calculate_average(&mut self, stat: &str) -> u64 {
        let mut sum = 0;
        let stats = self.client_stats_mut();

        for client_stat in stats.iter_mut() {
            if let Some(UserStats::Number(val)) = client_stat.get_user_stats(stat) {
                sum += val;
            }
        }

        sum / stats.len() as u64
    }

    /// Get the average number of vertices in the state-graphs across all instances.
    fn avg_statemachine_nodes(&mut self) -> u64 {
        self.calculate_average(USER_STAT_NODES)
    }

    /// Get the average number of edges in the state-graphs across all instances.
    fn avg_statemachine_edges(&mut self) -> u64 {
        self.calculate_average(USER_STAT_EDGES)
    }
}

/// A monitor that prints information about the state-graph in addition to all other info.
///
/// Works as a drop-in replacement for all other monitors.
#[derive(Clone, Debug)]
pub struct StateMonitor {
    client_stats: Vec<ClientStats>,
    start_time: Duration,
}
impl StateMonitor {
    /// Create a new StateMonitor
    pub fn new() -> Self {
        Self {
            client_stats: Vec::<ClientStats>::new(),
            start_time: current_time(),
        }
    }

    fn max_corpus_size(&self) -> u64 {
        let mut val = 0;

        for client_stat in &self.client_stats {
            val = std::cmp::max(val, client_stat.corpus_size);
        }

        val
    }
}

impl HasStateStats for StateMonitor {}

impl Monitor for StateMonitor {
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    fn start_time(&mut self) -> Duration {
        self.start_time
    }

    fn display(&mut self, msg: String, _sender: u32) {
        let num_nodes = self.avg_statemachine_nodes();
        let num_edges = self.avg_statemachine_edges();
        let corpus_size = self.max_corpus_size();
        let objective_size = self.objective_size();
        let execs = self.total_execs();
        let execs_per_sec = self.execs_per_sec();
        let cores = std::cmp::max(1, self.client_stats.len().saturating_sub(1));

        println!(
            "[butterfly::{}] uptime: {} | cores: {} | corpus: {} | objectives: {} | total execs: {} | exec/s: {} | nodes: {} | edges: {}",
            msg,
            format_duration_hms(&(current_time() - self.start_time)),
            cores,
            corpus_size,
            objective_size,
            execs,
            execs_per_sec,
            num_nodes,
            num_edges,
        );
    }
}

/// A monitor that periodically outputs a DOT representation of the state graph.
///
/// __Only available with feature__: `graphviz`
///
/// If there are multiple fuzzer instances this monitor writes the state graph of
/// each instance to the file separated by linebreaks.
///
/// # Example
/// ```
/// // Writes every 60 seconds into stategraph.dot
/// let monitor = GraphvizMonitor::new(
///    StateMonitor::new(),
///    "stategraph.dot",
///    60,
/// );
/// ```
#[cfg(feature = "graphviz")]
#[derive(Clone, Debug)]
pub struct GraphvizMonitor<M>
where
    M: Monitor,
{
    base: M,
    filename: PathBuf,
    last_update: Duration,
    interval: u64,
}

#[cfg(feature = "graphviz")]
impl<M> GraphvizMonitor<M>
where
    M: Monitor,
{
    /// Creates a new GraphvizMonitor.
    ///
    /// # Arguments
    /// - `monitor`: Other monitor that shall be wrapped
    /// - `filename`: Filename of the dot file
    /// - `interval`: Interval in seconds at which to write to the file
    pub fn new<P>(monitor: M, filename: P, interval: u64) -> Self
    where
        P: Into<PathBuf>,
    {
        Self {
            base: monitor,
            filename: filename.into(),
            last_update: current_time(),
            interval,
        }
    }
}

#[cfg(feature = "graphviz")]
impl<M> Monitor for GraphvizMonitor<M>
where
    M: Monitor,
{
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        self.base.client_stats_mut()
    }

    fn client_stats(&self) -> &[ClientStats] {
        self.base.client_stats()
    }

    fn start_time(&mut self) -> Duration {
        self.base.start_time()
    }

    fn display(&mut self, event_msg: String, sender_id: u32) {
        let cur_time = current_time();

        if (cur_time - self.last_update).as_secs() >= self.interval {
            self.last_update = cur_time;

            let mut file = File::create(&self.filename).expect("Failed to open DOT file");

            for stats in self.client_stats_mut() {
                if let Some(UserStats::String(graph)) = stats.get_user_stats(USER_STAT_STATEGRAPH) {
                    writeln!(&mut file, "{}", graph).expect("Failed to write DOT file");
                }
            }
        }

        self.base.display(event_msg, sender_id);
    }
}

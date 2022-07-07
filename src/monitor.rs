use crate::event::{USER_STAT_EDGES, USER_STAT_NODES};
use libafl::{
    bolts::{current_time, format_duration_hms},
    monitors::{ClientStats, Monitor, UserStats},
};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

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

        println!("[butterfly::{}] uptime: {} | cores: {} | corpus: {} | objectives: {} | total execs: {} | exec/s: {} | nodes: {} | edges: {}", msg, format_duration_hms(&(current_time() - self.start_time)), cores, corpus_size, objective_size, execs, execs_per_sec, num_nodes, num_edges,);
    }
}

/// A monitor that wraps another monitor and writes information
/// about the fuzzing campaign into a specified file.
///
/// The information includes most of the things printed on screen plus
/// state-graph info from [`HasStateStats`](crate::HasStateStats):
/// - time in seconds
/// - number of clients running
/// - corpus size
/// - objective size
/// - total executions
/// - executions per second
/// - number of vertices in state-graph
/// - number of edges in state-graph
///
/// The file format is CSV.
#[derive(Clone, Debug)]
pub struct FuzzerStatsWrapper<M>
where
    M: Monitor + HasStateStats,
{
    base: M,
    filename: PathBuf,
    last_update: Duration,
    interval: u64,
}

impl<M> FuzzerStatsWrapper<M>
where
    M: Monitor + HasStateStats,
{
    /// Create a FuzzerStatsWrapper from a given monitor.
    ///
    /// # Arguments
    /// - `monitor`: monitor to wrap
    /// - `filename`: path to the logfile where information is written to
    /// - `interval`: Number of seconds to wait between writes (e.g. 30 to write every 30 seconds)
    pub fn new(monitor: M, filename: &str, interval: u64) -> Self {
        Self {
            base: monitor,
            filename: PathBuf::from(filename),
            last_update: current_time(),
            interval,
        }
    }
}

impl<M> Monitor for FuzzerStatsWrapper<M>
where
    M: Monitor + HasStateStats,
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
        let now = current_time();

        if (now - self.last_update).as_secs() >= self.interval {
            self.last_update = now;

            let already_exists = self.filename.exists();

            if let Ok(mut file) = std::fs::OpenOptions::new().append(true).create(true).open(&self.filename) {
                let cores = std::cmp::max(1, self.client_stats().len().saturating_sub(1));
                let mut corpus_size = 0;
                let mut objective_size = 0;
                let mut execs = 0;
                let mut execs_per_sec = 0;

                if self.base.client_stats().len() <= 1 {
                    corpus_size = self.base.corpus_size();
                    objective_size = self.base.objective_size();
                    execs = self.base.total_execs();
                    execs_per_sec = self.base.execs_per_sec();
                } else {
                    for client_stat in self.base.client_stats_mut().iter_mut().skip(1) {
                        /* maximum corpus size */
                        corpus_size = std::cmp::max(corpus_size, client_stat.corpus_size);

                        /* sum of objectives */
                        objective_size += client_stat.objective_size;

                        /* total execs */
                        execs += client_stat.executions;

                        /* total exec/s */
                        execs_per_sec += client_stat.execs_per_sec(now);
                    }
                }

                let nodes = self.base.avg_statemachine_nodes();
                let edges = self.base.avg_statemachine_edges();

                // Write header
                if !already_exists {
                    let _ = writeln!(&mut file, "### butterfly::FuzzerStatsWrapper output ###");
                    let _ = writeln!(&mut file, "# time, cores, corpus count, crashes, total execs, exec/s, nodes, edges");
                }

                // Write info
                let _ = writeln!(&mut file, "{}, {}, {}, {}, {}, {}, {}, {}", now.as_secs(), cores, corpus_size, objective_size, execs, execs_per_sec, nodes, edges);
            } else {
                eprintln!("[butterfly::FuzzerStatsWrapper] Could not write to {}!", self.filename.display());
            }
        }

        self.base.display(event_msg, sender_id)
    }
}

/// Key for user stats.
///
/// [`StateFeedback`](crate::StateFeedback) writes the number of vertices in
/// [`StateObservers`](crate::StateObserver) state-graph into the user stats
/// of the monitor with this key.
pub static USER_STAT_NODES: &str = "statemachine_nodes";

/// Key for user stats.
///
/// [`StateFeedback`](crate::StateFeedback) writes the number of edges in
/// [`StateObservers`](crate::StateObserver) state-graph into the user stats
/// of the monitor with this key.
pub static USER_STAT_EDGES: &str = "statemachine_edges";

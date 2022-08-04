use libafl::{Error, Evaluator};
use pcap::{Capture, Offline};
use std::ffi::OsStr;
use std::path::PathBuf;

/// Signifies that an input consists of packets.
///
/// The type of a packet can be anything.    
/// If you want your packets to be plain bytearrays
/// then use [`BytesInput`](libafl::inputs::BytesInput) as `I`
/// but packets can also hold some semantical or meta information
/// as structs or enums.
///
/// # Example
/// The simplest type of input:
/// ```
/// struct PacketInput {
///     packets: Vec<BytesInput>,
/// }
///
/// impl HasPackets<BytesInput> for PacketInput {
///     fn packets(&self) -> &[BytesInput] {
///         &self.packets
///     }
///         
///     fn packets_mut(&mut self) -> &mut Vec<BytesInput> {
///         &mut self.packets
///     }
/// }
/// ```
/// A more complicated packet type:
/// ```
/// enum FTPCommand {
///     USER(BytesInput),
///     PASS(BytesInput),
///     // and so on...
/// }
///
/// struct FTPInput {
///     packets: Vec<FTPCommand>,
/// }
///
/// impl HasPackets<FTPCommand> for FTPInput {
///     fn packets(&self) -> &[FTPCommand] {
///         &self.packets
///     }
///         
///     fn packets_mut(&mut self) -> &mut Vec<FTPCommand> {
///         &mut self.packets
///     }
/// }
/// ```
pub trait HasPackets<I> {
    /// Get the inputs packets
    fn packets(&self) -> &[I];

    /// Get the inputs packets
    fn packets_mut(&mut self) -> &mut Vec<I>;
}

/// Signifies that an input can be constructed from a packet capture.
///
/// Use it in conjunction with [`load_pcaps`].
pub trait HasPcapRepresentation<I> {
    /// Given a packet capture, parse the packets and construct an input
    fn from_pcap(capture: Capture<Offline>) -> Result<I, Error>;

    //TODO: maybe to_pcap() ?
}

/// Helper function that loads pcap files from a given directory into the corpus.
///
/// It scans the directory for files ending with `.pcap` or `.pcapng` and loads them
/// via [`HasPcapRepresentation::from_pcap()`](crate::HasPcapRepresentation::from_pcap).
///
/// This is an equivalent to [`load_initial_inputs()`](libafl::state::StdState::load_initial_inputs) from LibAFL.
///
/// # Arguments
/// - `state`: libafls state
/// - `fuzzer`: libafls fuzzer
/// - `executor`: libafls executor
/// - `mgr`: libafls event manager
/// - `in_dir`: path to directory with pcap files
pub fn load_pcaps<S, Z, E, EM, I, P>(state: &mut S, fuzzer: &mut Z, executor: &mut E, mgr: &mut EM, in_dir: P) -> Result<(), Error>
where
    Z: Evaluator<E, EM, I, S>,
    I: HasPcapRepresentation<I>,
    P: Into<PathBuf>,
{
    for entry in std::fs::read_dir(&in_dir.into())? {
        let entry = entry?;
        let path = entry.path();

        let attributes = std::fs::metadata(&path);

        if attributes.is_err() {
            continue;
        }

        let attr = attributes?;

        if attr.is_file() && attr.len() > 0 {
            if path.extension() == Some(OsStr::new("pcapng")) || path.extension() == Some(OsStr::new("pcap")) {
                println!("[butterfly] Loading pcap {}...", path.display());
                let input = I::from_pcap(Capture::from_file(path).expect("invalid pcap format"))?;
                let _ = fuzzer.evaluate_input(state, executor, mgr, input)?;
            }
        } else if attr.is_dir() {
            load_pcaps(state, fuzzer, executor, mgr, path)?;
        }
    }

    Ok(())
}

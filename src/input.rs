use libafl::{
    Error,
    Evaluator,
};
use pcap::{Capture, Offline};
use std::path::Path;
use std::ffi::OsStr;

pub trait HasPackets<I> {
    fn packets(&self) -> &[I];
    
    fn packets_mut(&mut self) -> &mut Vec<I>;
}

pub trait HasPcapRepresentation<I> {
    fn from_pcap(capture: Capture<Offline>) -> Result<I, Error>;
    
    //TODO: maybe to_pcap() ?
}

pub fn load_pcaps<S, Z, E, EM, I>(state: &mut S, fuzzer: &mut Z, executor: &mut E, mgr: &mut EM, in_dir: &Path) -> Result<(), Error> 
where
    Z: Evaluator<E, EM, I, S>,
    I: HasPcapRepresentation<I>,
{
    for entry in std::fs::read_dir(in_dir)? {
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
            load_pcaps(state, fuzzer, executor, mgr, &path)?;
        }
    }
    
    Ok(())
}

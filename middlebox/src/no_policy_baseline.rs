use log::info;
use nfq::{Queue, Verdict, Message};

pub fn netfilter() -> std::io::Result<()> {
    let mut queue = Queue::open()?; 
    queue.bind(0)?;
    loop {
        let mut msg = queue.recv()?;
        info!("Received msg");
        // print!("{:?}", msg);
        let verdict = Verdict::Accept;
        msg.set_verdict(verdict);
        queue.verdict(msg)?;
    }
    Ok(())
}
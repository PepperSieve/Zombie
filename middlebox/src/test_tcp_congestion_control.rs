use std::thread::sleep;

use std::time::Duration;
use nfq::{Queue, Verdict, Message};

pub fn netfilter(batch_size: usize) -> std::io::Result<()> {
    let mut queue = Queue::open()?; 
    queue.bind(0)?;
    // accept handshake
    for _ in 0..10 {
        let mut msg = queue.recv()?;
        let verdict = Verdict::Accept;
        msg.set_verdict(verdict);
        queue.verdict(msg)?;
    }
    loop {
        let mut msgs = Vec::new();
        for _ in 0..batch_size {
            let msg = queue.recv()?;
            print!("{:?}", msg);
            msgs.push(msg);
        }
        for mut msg in msgs {
            let verdict = Verdict::Accept;
            sleep(Duration::from_millis(100));
            msg.set_verdict(verdict);
            queue.verdict(msg)?;
        }
    }
    Ok(())
}
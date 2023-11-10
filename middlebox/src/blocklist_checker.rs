use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

#[derive(Clone)]
pub struct BlocklistChecker {
    blocklist: Vec<String>
}

impl BlocklistChecker {
    pub fn new(blocklist_path: String) -> Self {
        println!("will construct blocklist");
        let mut blocklist = Vec::<String>::new();
        if let Ok(lines) = read_lines(blocklist_path) {
            // Consumes the iterator, returns an (Optional) String
            for line in lines {
                if let Ok(name) = line {
                    let name = [".", &name].join("");
                    let name: String = name.chars().rev().collect();
                    blocklist.push(name);
                }
            }
        }
        println!("will sort blocklist");
        blocklist.sort();
        println!("finish sort blocklist");
        BlocklistChecker { blocklist }
    }

    pub fn contains(&self, name: String) -> bool {
        if self.blocklist.len() == 0 {
            return false;
        }
        let name = [".", &name].join("");
        let name: String = name.chars().rev().collect();
        match self.blocklist.binary_search(&name) {
            Ok(_) => true,
            Err(idx) => {
                let left = if idx == 0 { 0 } else { idx - 1 };
                let right = idx;
                name.starts_with(&self.blocklist[left]) || name.starts_with(&self.blocklist[right]) 
            },
        }
    }
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
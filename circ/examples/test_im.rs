use std::time::Instant;

use im;
use libc;
use rand::{distributions::Alphanumeric, Rng};

fn get_rand_str() -> String {
    rand::thread_rng()
    .sample_iter(&Alphanumeric)
    .take(10000)
    .map(char::from)
    .collect()
}

fn foo(map: &mut im::OrdMap<String, String>, arr1: &Vec<String>, arr2: &Vec<String>) {
    let timer = Instant::now();
    let mut map = im::OrdMap::<String, String>::new();
    for idx in 0..10000 {
        map.insert(arr1[idx].clone(), arr2[idx].clone());
    }
    println!("takes {}", timer.elapsed().as_millis());
}

fn main() {
    // let x = unsafe { libc::malloc(4096 * 100000) };
    // unsafe { libc::memset(x, 1, 4096 * 100000) };
    // unsafe { libc::free(x) };
    let mut map = im::OrdMap::<String, String>::new();
    let mut str_arr1 = Vec::<String>::new();
    let mut str_arr2 = Vec::<String>::new();
    for _ in 0..10000 {
        str_arr1.push(get_rand_str());
    }
    for _ in 0..10000 {
        str_arr2.push(get_rand_str());
    }
    foo(&mut map, &str_arr1, &str_arr2);
    let mut map2 = im::OrdMap::<String, String>::new();
    foo(&mut map2, &str_arr1, &str_arr2);
    foo(&mut map, &str_arr1, &str_arr2);
    println!("changed");
}
use std::env;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::process;
use flate2::read::ZlibDecoder;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args[1] == "init" {
        fs::create_dir(".git").unwrap();
        fs::create_dir(".git/objects").unwrap();
        fs::create_dir(".git/refs").unwrap();
        fs::write(".git/HEAD", "ref: refs/heads/main\n").unwrap();
        println!("Initialized git directory")
    } else if args[1] == "cat-file" {
        if args.len() < 4 || args[2] != "-p" {
            println!("usage: {} cat-file -p <hash-of-blob>", args[0]);
            process::exit(1);
        }
        let blob_hash = &args[3];
        if blob_hash.len() != 40 {
            println!("Bad hash {}", blob_hash.len());
            process::exit(1);
        }
        let filename = &format!(".git/objects/{}/{}", blob_hash.chars().take(2).collect::<String>(), blob_hash.chars().skip(2).collect::<String>());
        let file = File::open(filename);

        if file.is_ok() {
            let file = file.unwrap();
            let reader = BufReader::new(file);

            let mut decoder = ZlibDecoder::new(reader);

            let mut contents = String::new();
            if decoder.read_to_string(&mut contents).is_err() {
                println!("Error decoding blob contents");
                process::exit(1);
            }
            let byte_contents = contents.bytes().skip_while(|x| *x != 0u8).skip(1).collect::<Vec<u8>>();
            contents = String::from_utf8(byte_contents).expect("valid UTF-8");

            print!("{}", contents);
            
        } else {
            println!("{} is err", filename);
            process::exit(1);
        }

    } else {
        println!("unknown command: {}", args[1]);
        process::exit(1);
    }
}

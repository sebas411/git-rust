use std::env;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::io::prelude::*;
use std::path::Path;
use std::process;
use std::vec;
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;
use sha1::{Sha1, Digest};

fn cat_file(blob_hash: &str) {
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
        println!("{} is not a valid hash for an object", blob_hash);
        process::exit(1);
    }
}

fn hash_object(filename: &str, write_object: bool) {
    let file = File::open(filename);

    if file.is_ok() {
        let mut file = file.unwrap();
        let mut contents = String::new();
        let mut to_write: Vec<u8> = vec![];

        // get file content
        if file.read_to_string(&mut contents).is_err() {
            println!("Error reading '{}' to a string", filename);
            process::exit(1);
        }

        // get blob object format
        let header = format!("blob {}", contents.len());
        to_write.extend(header.as_bytes());
        to_write.push(0 as u8);
        to_write.extend(contents.as_bytes());

        // get hash
        let mut hasher = Sha1::new();
        hasher.update(&to_write);
        let result = hasher.finalize();
        let mut blob_hash = String::new();
        for byte in result {
            blob_hash.push_str(&format!("{:02x}", byte));
        }
        println!("{}", blob_hash);

        // write object (if indicated)
        if write_object {
            let dir = format!(".git/objects/{}/", blob_hash.chars().take(2).collect::<String>());
            let filename = blob_hash.chars().skip(2).collect::<String>();

            // create directory if doesn't exist
            if !Path::new(&dir).exists() {
                if fs::create_dir(&dir).is_err() {
                    println!("Couldn't create dir");
                    process::exit(1);
                }
            }

            // write file if doesn't exist
            let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
            e.write_all(&to_write).unwrap();
            let compressed_bytes = e.finish();
            if compressed_bytes.is_ok() {
                let compressed_bytes = compressed_bytes.unwrap();
                if fs::write(dir + &filename, &compressed_bytes).is_err() {
                    println!("Couldn't write to file");
                }
            }
        }

    } else {
        println!("Problem opening '{}' file", filename);
        process::exit(1);
    }

}

fn ls_tree(tree_hash: &str, name_only: bool) {
    let filename = &format!(".git/objects/{}/{}", tree_hash.chars().take(2).collect::<String>(), tree_hash.chars().skip(2).collect::<String>());
    let file = File::open(filename);

    if file.is_ok() {
        let file = file.unwrap();
        let reader = BufReader::new(file);

        let mut decoder = ZlibDecoder::new(reader);

        let mut contents: Vec<u8> = vec![];
        if decoder.read_to_end(&mut contents).is_err() {
            println!("Error decoding blob contents");
            process::exit(1);
        }
        let mut i = 0;
        // skip "tree <size>"
        loop {
            if i > contents.len() || contents[i] == 0 {
                i += 1;
                break;
            }
            i += 1
        }

        let mut my_tree: Vec<(String, String, String)> = vec![];

        while contents.len() > i {
            let mut file_mode = String::new();
            while i < contents.len() && contents[i] as char != ' ' {
                file_mode.push(contents[i] as char);
                i += 1;
            }
            i += 1;
            
            let mut file_name = String::new();
            while i < contents.len() && contents[i] != 0 {
                file_name.push(contents[i] as char);
                i += 1;
            }
            i += 1;

            let mut file_hash = String::new();
            for byte in contents[i..i+20].bytes() {
                let byte = byte.unwrap();
                file_hash.push_str(&format!("{:02x}", byte));

            }
            i += 20;

            my_tree.push((file_mode, file_name, file_hash));
        }

        if name_only {
            for item in my_tree {
                println!("{}", item.1);
            }
        } else {
            for item in my_tree {
                let file_type;
                if item.0 == "40000" {
                    file_type = "tree";
                    print!("0");
                } else {
                    file_type = "blob";
                }
                println!("{} {} {}    {}", item.0, file_type, item.2, item.1)
            }
        }
    } else {
        println!("{} is not a valid hash for a tree", tree_hash);
        process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args[1] == "init" {
        fs::create_dir(".git").unwrap();
        fs::create_dir(".git/objects").unwrap();
        fs::create_dir(".git/refs").unwrap();
        fs::write(".git/HEAD", "ref: refs/heads/main\n").unwrap();
        println!("Initialized git directory")
    }
    // cat-file
    else if args[1] == "cat-file" {
        if args.len() < 4 || args[2] != "-p" {
            println!("usage: {} cat-file -p <hash-of-blob>", args[0]);
            process::exit(1);
        }
        let blob_hash = &args[3];
        if blob_hash.len() != 40 {
            println!("Bad hash {}", blob_hash.len());
            process::exit(1);
        }
        cat_file(blob_hash);
    }
    // hash-object
    else if args[1] == "hash-object" {
        if args.len() < 3 || args.len() > 4 {
            println!("usage: {} hash-object [-w] <filename>", args[0]);
            process::exit(1);
        }
        let mut filename: &str = &"".to_string();
        let mut write_object = false;
        for arg in &args[2..] {
            if arg == "-w" {
                write_object = true;
            } else {
                filename = arg
            }
        }
        hash_object(filename, write_object);

    }
    // ls-tree
    else if args[1] == "ls-tree" {
        if args.len() < 3 || args.len() > 4 {
            println!("usage: {} ls-tree [--name-only] <hash-of-tree>", args[0]);
            process::exit(1);
        }
        let mut tree_hash = &String::new();
        let mut name_only = false;
        for arg in &args[2..] {
            if arg == "--name-only" {
                name_only = true;
            } else {
                tree_hash = arg
            }
        }
        if tree_hash.len() != 40 {
            println!("Bad hash {}", tree_hash.len());
            process::exit(1);
        }
        ls_tree(&tree_hash, name_only);
    }
    else {
        println!("unknown command: {}", args[1]);
        process::exit(1);
    }
}

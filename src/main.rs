use std::env;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read, Cursor};
use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process;
use std::vec;
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;
use sha1::{Sha1, Digest};
use chrono::Local;

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

fn hash_object(filename: &str, write_object: bool) -> [u8; 20] {
    let file = File::open(filename);
    let mut returned_hash = [0u8; 20];

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
        to_write.push(0u8);
        to_write.extend(contents.as_bytes());

        // get hash
        let mut hasher = Sha1::new();
        hasher.update(&to_write);
        let result = hasher.finalize();
        returned_hash[..result.len()].copy_from_slice(&result[..]);
        let mut blob_hash = String::new();
        for byte in result {
            blob_hash.push_str(&format!("{:02x}", byte));
        }

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
    return returned_hash;

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

fn write_tree(dir: &str) -> [u8; 20] {
    let mut readable_dir: Vec<_> = fs::read_dir(dir).unwrap().filter_map(|entry| entry.ok()).collect();
    readable_dir.sort_by_key(|e| e.file_name());
    let mut content: Vec<u8> = vec![];

    // get entries from dirs and files
    for entry in readable_dir {
        let path = entry.path();
        let filename = path.file_name().unwrap().to_str().unwrap();
        if filename == ".git" {
            continue;
        }
        if path.is_dir() {
            let tree_hash = write_tree(path.to_str().unwrap());
            let mode_and_name = format!("40000 {}", filename);
            content.extend(mode_and_name.bytes());
            content.push(0);
            content.extend(tree_hash);
        } else {
            let metadata = fs::symlink_metadata(&path).unwrap();
            let permissions = metadata.permissions();
            let mode: u16 = permissions.mode() as u16;
            let executable: u16 = 493u16;
            let is_executable = (mode & executable) == executable;
            let is_symlink = metadata.file_type().is_symlink();
            let tree_mode;

            if is_symlink {
                tree_mode = "120000";
            } else if is_executable {
                tree_mode = "100755";
            } else {
                tree_mode = "100644";
            }

            let object_hash = hash_object(path.to_str().unwrap(), true);
            let mode_and_name = format!("{} {}", tree_mode, filename);
            content.extend(mode_and_name.bytes());
            content.push(0);
            content.extend(object_hash);
        }
    }
    let mut to_write: Vec<u8> = vec![];
    let header = format!("tree {}", content.len());
    to_write.extend(header.bytes());
    to_write.push(0u8);
    to_write.extend(content);

    // get hash
    let mut hasher = Sha1::new();
    hasher.update(&to_write);
    let result = hasher.finalize();
    let mut returned_hash = [0u8; 20];
    returned_hash[..result.len()].copy_from_slice(&result[..]);
    let mut tree_hash = String::new();
    for byte in result {
        tree_hash.push_str(&format!("{:02x}", byte));
    }

    // write tree
    let dir = format!(".git/objects/{}/", tree_hash.chars().take(2).collect::<String>());
    let filename = tree_hash.chars().skip(2).collect::<String>();

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

    return returned_hash;
}

fn commit_tree(tree_hash: &str, parent_commit_hash: Option<&str>, message: &str) {
    let mut content = String::new();
    content.push_str(&format!("tree {}\n", tree_hash));
    
    if parent_commit_hash.is_some() {
        content.push_str(&format!("parent {}\n", parent_commit_hash.unwrap()).to_string());
    }

    let now = Local::now();
    let seconds = now.timestamp();
    let timezone_offset = now.format("%z").to_string();

    content.push_str(&format!("author example <commiter@example.com> {} {}\n", seconds, timezone_offset));
    content.push_str(&format!("committer example <commiter@example.com> {} {}\n\n", seconds, timezone_offset));

    content.push_str(message);
    content.push('\n');

    let mut to_write: Vec<u8> = vec![];
    let header = format!("commit {}", content.bytes().len());
    to_write.extend(header.bytes());
    to_write.push(0u8);
    to_write.extend(content.bytes());

    // get hash
    let mut hasher = Sha1::new();
    hasher.update(&to_write);
    let result = hasher.finalize();
    let mut commit_hash = String::new();
    for byte in result {
        commit_hash.push_str(&format!("{:02x}", byte));
    }

    println!("{}", commit_hash);

    // write tree
    let dir = format!(".git/objects/{}/", commit_hash.chars().take(2).collect::<String>());
    let filename = commit_hash.chars().skip(2).collect::<String>();

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

fn packet_line(line: &str) -> String {
    format!("{:04x}{}", line.len() + 4, line)
}

/// This function saves the pack file and also initializes
/// the local repo with obtained refs
/// 
/// ## Arguments
///
/// * `url` - The repo url
/// * `dir_name` - Name of the directory to initialize and save pack
///
/// ## Example
///
/// ```
/// save_pack_file("https://github.com/example/repo", "my-dir");
/// ```
async fn save_pack_file(url: &str, dir_name: &str) {
    let client = reqwest::Client::new();
    
    // get refs
    let result = client.get(format!("{}/info/refs?service=git-upload-pack", url)).send().await;
    if result.is_err() {
        println!("Error sending the request");
        process::exit(1);
    }
    let response_text = result.unwrap().text().await.unwrap();
    let mut refs: Vec<String> = vec![];
    let mut skip_chars = 0;
    let mut start = false;
    while skip_chars < response_text.len() {
        let len_hex = response_text.chars().skip(skip_chars).take(4).collect::<String>();
        let len_dec = u32::from_str_radix(&len_hex, 16).unwrap();
        if len_hex == "0000" {
            if start {
                break
            } else {
                start = true;
                skip_chars += 4;
            }
        } else {
            if start {
                refs.push(response_text.chars().skip(skip_chars + 4).take(len_dec as usize - 4).collect::<String>());
            }
        }
        skip_chars += len_dec as usize;
    }
    refs[0] = refs[0].chars().take_while(|c| *c != '\0').collect::<String>();
    refs[0].push('\n');

    let mut main_id = String::new();
    let mut main_name = String::new();
    let mut searching = false;
    for i in 0..refs.len() {
        let reference = &refs[i];
        let sha1_id = reference.chars().take_while(|c| *c != ' ').collect::<String>();
        let reference_name = reference.chars().skip_while(|c| *c != ' ').skip(1).take_while(|c| *c != '\n').collect::<String>();
        if i == 0 {
            main_id = sha1_id;
            if reference_name == "HEAD" {
                searching = true;
            } else {
                main_name = reference_name;
            }
        } else {
            if searching {
                if sha1_id == main_id {
                    searching = false;
                    main_name = reference_name;
                }
            }
        }
    }

    // initialize local git repo
    fs::create_dir(dir_name).unwrap();
    fs::create_dir(format!("{}/.git", dir_name)).unwrap();
    fs::create_dir(format!("{}/.git/objects", dir_name)).unwrap();
    fs::create_dir(format!("{}/.git/objects/pack", dir_name)).unwrap();
    fs::create_dir(format!("{}/.git/refs", dir_name)).unwrap();
    fs::create_dir(format!("{}/.git/refs/heads", dir_name)).unwrap();
    fs::write(format!("{}/.git/HEAD", dir_name), format!("ref: {}\n", main_name)).unwrap();
    fs::write(format!("{}/.git/{}", dir_name, main_name), main_id).unwrap();
    
    // ask for pack file and store it
    let mut my_request = String::new();
    for reference in refs {
        my_request.push_str(&packet_line(&format!("want {}", reference)));
    }
    my_request.push_str("0000");
    my_request.push_str(&packet_line("done\n"));

    let response = client.post(format!("{}/git-upload-pack", url)).body(my_request).header("Content-Type", "application/x-git-upload-pack-request").send().await.unwrap();
    let mut data = response.bytes().await.unwrap().to_vec();
    let first4bytes = String::from_utf8(data[..4].to_vec()).unwrap();
    if first4bytes == "0008" {
        data = data[8..].to_vec();
    }
    fs::write(format!("{}/.git/objects/pack/cloned.pack", dir_name), data).unwrap();
}

fn unpack_pack_file(dir_name: &str) {
    let content = fs::read(format!("{}/.git/objects/pack/cloned.pack", dir_name)).unwrap();
    let object_num = i32::from_be_bytes(content[8..12].try_into().unwrap());

    let mut processed = 12;

    for _ in 0..object_num {
        let content = content[processed..].to_vec();
        
        let object_type = (content[0] & 112u8) >> 4;

        let mut num_continue = content[0] > 127;
        let mut current_byte = 0;
        let mut object_size: u64 = (content[0] & 15u8).into();
        while num_continue {
            current_byte += 1;
            num_continue = content[current_byte] > 127;
            object_size = object_size | ((content[current_byte] & 127u8) as u64) << (4 + 7 * (current_byte - 1));
        }
        let content = content[current_byte+1..].to_vec();

        let mut to_write: Vec<u8> = vec![];
        // blob, commit, trees
        if object_type < 4 && object_type != 0 {
            let cursor = Cursor::new(content);

            let mut decoder = ZlibDecoder::new(cursor);

            let mut decoded_contents: Vec<u8> = vec![0u8; object_size as usize];
            if decoder.read(&mut decoded_contents).is_err() {
                println!("Error decoding blob contents");
                process::exit(1);
            }

            let object_type_name;
            if object_type == 1 {
                object_type_name = String::from("commit");
            } else if object_type == 2 {
                object_type_name = String::from("tree");
            } else if object_type == 3 {
                object_type_name = String::from("blob");
            } else {
                object_type_name = String::from("invalid");
            }
            let header = format!("{} {}", object_type_name, object_size);
            to_write.extend(header.bytes());
            to_write.push(0u8);
            to_write.extend(decoded_contents);
            let total_in = decoder.total_in() as usize;
            processed += total_in + current_byte + 1;
        }
        // REF_DELTA
        else if object_type == 7 {
            let reference_hash = &content[..20];
            let mut reference_hash_hex = String::new();
            for i in 0..20 {
                let byte = reference_hash[i];
                reference_hash_hex.push_str(&format!("{:02x}", byte));
            }

            // decode instructions
            let content = content[20..].to_vec();
            let cursor = Cursor::new(content);
            let mut decoder = ZlibDecoder::new(cursor);
            let mut decoded_contents: Vec<u8> = vec![0u8; object_size as usize];
            if decoder.read(&mut decoded_contents).is_err() {
                println!("Error decoding blob contents");
                process::exit(1);
            }
            let total_in = decoder.total_in() as usize;
            processed += total_in + current_byte + 21;
            let mut bytes_to_skip = 0;
            while decoded_contents[bytes_to_skip] > 127 {
                bytes_to_skip += 1;
            }
            bytes_to_skip += 1;
            while decoded_contents[bytes_to_skip] > 127 {
                bytes_to_skip += 1;
            }
            bytes_to_skip += 1;
            let instructions = decoded_contents[bytes_to_skip..].to_vec();
            
            // get reference object on memory
            let filename = &format!("{}/.git/objects/{}/{}", dir_name, reference_hash_hex.chars().take(2).collect::<String>(), reference_hash_hex.chars().skip(2).collect::<String>());
            let file = File::open(filename).unwrap();
            let reader = BufReader::new(file);
            let mut decoder = ZlibDecoder::new(reader);
            let mut reference_contents: Vec<u8> = vec![];
            if decoder.read_to_end(&mut reference_contents).is_err() {
                println!("Error decoding reference object contents");
                process::exit(1);
            }
            let reference_object_type = reference_contents.clone().into_iter().take_while(|x| *x as char != ' ').collect::<Vec<u8>>();
            let reference_contents = reference_contents.into_iter().skip_while(|x| *x != 0u8).skip(1).collect::<Vec<u8>>();
            
            // process file (copies and adds)
            let mut new_file_contents:Vec<u8> = vec![];
            let mut current_byte = 0;
            while current_byte < instructions.len() {
                let is_copy = instructions[current_byte] > 127;
                
                if is_copy {
                    let mut size_to_copy= 0;
                    let mut offset = 0;

                    let mut bytes_for_size = vec![];
                    let mut bytes_for_offset = vec![];
                    if instructions[current_byte] & 1 > 0 {
                        bytes_for_offset.push(24);
                    }
                    if instructions[current_byte] & 2 > 0 {
                        bytes_for_offset.push(16);
                    }
                    if instructions[current_byte] & 4 > 0 {
                        bytes_for_offset.push(8);
                    }
                    if instructions[current_byte] & 8 > 0 {
                        bytes_for_offset.push(0);
                    }
                    if instructions[current_byte] & 16 > 0 {
                        bytes_for_size.push(24);
                    }
                    if instructions[current_byte] & 32 > 0 {
                        bytes_for_size.push(16);
                    }
                    if instructions[current_byte] & 64 > 0 {
                        bytes_for_size.push(8);
                    }
                    current_byte += 1;
                    for byte in bytes_for_offset {
                        let my_byte = (instructions[current_byte] as u32) << byte;
                        offset = offset | my_byte;
                        current_byte += 1
                    }
                    for byte in bytes_for_size {
                        let my_byte = (instructions[current_byte] as u32) << byte;
                        size_to_copy = size_to_copy | my_byte;
                        current_byte += 1
                    }
                    let offset = offset.to_be() as usize;
                    let size_to_copy = size_to_copy.to_be() as usize;
                    new_file_contents.extend(&reference_contents[offset..offset+size_to_copy]);
 
                } else {
                    let size_to_add = (instructions[current_byte] & 127u8) as usize;
                    current_byte += 1;
                    new_file_contents.extend(&instructions[current_byte..(current_byte + size_to_add)]);
                    current_byte += size_to_add;
                }
            }
            let header = String::from(format!("{} {}", String::from_utf8(reference_object_type).unwrap(), new_file_contents.len()));
            to_write.extend(header.bytes());
            to_write.push(0u8);
            to_write.extend(new_file_contents);
        }
        // other object type
        else {
            println!("Unsupported object type");
            process::exit(1);
        }

        // get hash
        let mut hasher = Sha1::new();
        hasher.update(&to_write);
        let result = hasher.finalize();
        let mut object_hash = String::new();
        for byte in result {
            object_hash.push_str(&format!("{:02x}", byte));
        }

        // write object
        let dir = format!("{}/.git/objects/{}/", dir_name, object_hash.chars().take(2).collect::<String>());
        let filename = object_hash.chars().skip(2).collect::<String>();

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
}

async fn git_clone(url: &str, dir_name: &str) {
    save_pack_file(url, dir_name).await;
    unpack_pack_file(dir_name);
}

#[tokio::main]
async fn main() {
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
        let result = hash_object(filename, write_object);
        let mut blob_hash = String::new();
        for byte in result {
            blob_hash.push_str(&format!("{:02x}", byte));
        }
        println!("{}", blob_hash);
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
    // write-tree
    else if args[1] == "write-tree" {
        if args.len() > 2 {
            println!("usage: {} write-tree", args[0]);
            process::exit(1);
        }
        let result = write_tree(".");
        let mut tree_hash = String::new();
        for byte in result {
            tree_hash.push_str(&format!("{:02x}", byte));
        }
        println!("{}", tree_hash);
    }
    // commit-tree
    else if args[1] == "commit-tree" {
        if args.len() < 5 || args.len() > 7 {
            println!("usage: {} commit-tree <tree_hash> -m <commit-message> [-p <parent-commit-hash>]", args[0]);
            process::exit(1);
        }
        let mut set_parent = false;
        let mut set_message = false;
        let mut tree_hash = String::new();
        let mut parent_commit_hash: Option<&str> = None;
        let mut message = String::new();

        for i in 2..args.len() {
            if set_parent {
                set_parent = false;
                parent_commit_hash = Some(&args[i]);
            } else if set_message {
                set_message = false;
                message = args[i].to_string();
            } else if args[i] == "-p" {
                set_parent = true;
            } else if args[i] == "-m" {
                set_message = true;
            } else {
                tree_hash = args[i].to_string();
            }
        }
        if tree_hash == "" {
            println!("Error: Didn't get tree hash for commit");
            process::exit(1);
        }

        commit_tree(&tree_hash, parent_commit_hash, &message);
    }
    // clone
    else if args[1] == "clone" {
        if args.len() != 4 {
            println!("usage: {} clone <url> <directory>", args[0]);
            process::exit(1);
        }
        let url = &args[2];
        let dir_name = &args[3];
        git_clone(url, dir_name).await;
    }
    else {
        println!("unknown command: {}", args[1]);
        process::exit(1);
    }
}

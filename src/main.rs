use std::fs;
use std::io;
// use std::path::Path;
use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};

const NR_KEY: &[u8; 16] = b"\x18\xF6\x32\x66\x05\xBD\x17\x8A\x55\x24\x52\x3A\xC0\xA0\xC6\x09";
const IV_SIZE: usize = 0x10;
const BND4_HEADER_LEN: usize = 64;
const BND4_ENTRY_HEADER_LEN: usize = 32;
const TARGET_ENTRY_NUM: usize = 10;
const SLOT_NICKNAME_INDEX: usize = 6498;
const SLOT_DATA_LEN: usize = 656;
const SESSION_DATA_LEN: usize = 1872;
const NICKNAME_LEN: usize = 32;
const NL_LIST: [&str; 10] = ["Gladius (글라디우스)", "Adel (에델레)", "Gnoster (그노스터)", "Maris (마리스)", "Libra (리브라)", "Fulghor (풀고르)", "Caligo (칼리고)", "Heolstor (나멜레스)", "Harmonia (하르모니아)", "Straghess (스트라게스)"];

macro_rules! my_dbg {
    ($val:expr) => {
        if cfg!(debug_assertions) {
            dbg!($val);
        }
    }
}
macro_rules! enter_exit {
    ($code:expr, $msg:expr) => {{
        if $code != 0 {
            eprintln!("{}", $msg);
        } else {
            println!("{}", $msg);
        }
    println!("\nPress Enter to Exit...");
    let _ = io::stdin().read_line(&mut String::new());
    ::std::process::exit($code);
    }}
}

// fn save_file<P: AsRef<Path>>(file_path: P, data: &[u8]) {
//     let path = file_path.as_ref();
//     if let Some(parent_dir) = path.parent() {
//         if !parent_dir.exists() {
//             fs::create_dir_all(parent_dir).expect("폴더 생성에 실패했습니다.");
//         }
//     }

//     fs::write(path, data).expect("파일 저장에 실패했습니다.")
// }
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

struct Bnd4Entry {
    size: usize,
    offset: usize,
}

impl Bnd4Entry {
    fn new(size: usize, offset: usize) -> Self {
        Bnd4Entry {
            size,
            offset,
        }
    }

    fn decrypt(&self, raw: &[u8]) -> Vec<u8> {
        let entry_data = &raw[self.offset..self.offset + self.size];
        let iv: [u8; 16] = (&entry_data[..IV_SIZE]).try_into().unwrap();
        let encrypted_payload = &entry_data[IV_SIZE..];

        let mut buffer = encrypted_payload.to_vec();

        let decrypted_data = Aes128CbcDec::new(NR_KEY.into(), &iv.into()).decrypt_padded::<Pkcs7>(&mut buffer).unwrap();
        
        // save_file("./test/USERDATA_output", decrypted_data);

        return decrypted_data.to_vec()
    }
}

#[derive(Debug)]
struct Session<'a> {
    nickname: &'a [u8],
    id: u32,
    idx: usize,
}

fn find_last_session<'a>(target: &'a [u8], nicknames: &[&'a [u8]]) -> Option<Session<'a>> {
    let search_start = SLOT_NICKNAME_INDEX + SLOT_DATA_LEN * 10;
    if target.len() < search_start { return None; }

    let rscl = target[search_start..].windows(4).position(|window| window == b"RSCL");
    my_dbg!(rscl);
    let search_end = match rscl {
        Some(idx) => (search_start + idx + 20 + SESSION_DATA_LEN * 101).min(target.len()),
        None => (search_start + 8592 + SESSION_DATA_LEN * 101).min(target.len()),
    };
    my_dbg!(search_end);

    nicknames.iter().filter_map(|&nickname| {
        target[search_start..search_end]
            .windows(nickname.len())
            .enumerate()
            .filter(|(_, window)| *window == nickname)
            .filter_map(|(relative_idx, _)| {
                let i = search_start + relative_idx;
                if i >= 100 && target.get(i - 20) == Some(&0) {
                    let s = i - 100;
                    let sid_idx = s + 12;

                    target.get(sid_idx..sid_idx + 4)
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(|array| Session {
                            nickname,
                            id: u32::from_le_bytes(array),
                            idx: s,
                        })

                } else {
                    None
                }
            })
            .max_by_key(|session| session.id)
    })
    .max_by_key(|session| session.id)
}


fn main() {
    let raw = match fs::read("NR0000.sl2") {
        Ok(data) => data,
        Err(_) => {
            enter_exit!(-1, "[ERROR] 세이브 파일(NR0000.sl2)을 찾을 수 없습니다.");
        }
    };

    if raw.get(0..4) != Some(b"BND4") {
        enter_exit!(-1, "[ERROR] SL2 파일이 아닙니다.");
    }

    let bnd4_entries = i32::from_le_bytes(raw[0x0c..0x10].try_into().unwrap()) as usize;
    my_dbg!(bnd4_entries);

    let unicode_flag = raw[0x30] == 1;
    my_dbg!(unicode_flag);

    let pos = BND4_HEADER_LEN + (BND4_ENTRY_HEADER_LEN * TARGET_ENTRY_NUM);
    let entry_header = &raw[pos..pos + BND4_ENTRY_HEADER_LEN];

    let entry_size = i32::from_le_bytes(entry_header[0x08..0x0c].try_into().unwrap()) as usize;
    let entry_data_offset = i32::from_le_bytes(entry_header[16..20].try_into().unwrap()) as usize;
    let entry_name_offset = i32::from_le_bytes(entry_header[0x14..0x18].try_into().unwrap()) as usize;
    my_dbg!(entry_name_offset);

    let entry_name = std::str::from_utf8(&raw[entry_name_offset..entry_name_offset + 24]).unwrap().replace('\0', "");
    my_dbg!(entry_name);

    // let entry = Bnd4Entry::new(TARGET_ENTRY_NUM, entry_size, entry_data_offset);
    let entry = Bnd4Entry::new(entry_size, entry_data_offset);
    let decrypted_data = entry.decrypt(&raw);
    
    let nicknames: Vec<&[u8]> = (0..10)
        .map(|i| {
            let n_idx = SLOT_NICKNAME_INDEX + SLOT_DATA_LEN * i;
            &decrypted_data[n_idx..n_idx + NICKNAME_LEN]
        })
        .filter(|nickname| nickname.iter().any(|&b| b != 0))
        .collect();

    if let Some(last_session) = find_last_session(&decrypted_data, &nicknames) {
        let clean_nick: String = last_session.nickname.iter()
            .filter(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();

        println!("Nickname: {}", clean_nick);
        println!("Last Session ID: {}", last_session.id);
        my_dbg!(last_session.idx);

        if let Some(boss_bytes) = decrypted_data.get(last_session.idx + 54..last_session.idx + 56) {
            my_dbg!(boss_bytes);
            let boss_ix = boss_bytes[0] as usize;
            let boss_name = match NL_LIST.get(boss_ix) {
                Some(name) => name,
                None => {
                    // save_file("./test/ERR_USERDATA_output", &decrypted_data);
                    enter_exit!(-1, "[ERROR] Boss를 식별할 수 없습니다. 잠시 후 다시 시도해 주세요.");
                }
            };
            println!("Boss: {}", boss_name);

            let everdark = if boss_bytes[1] == 1 { "YES" } else { "No" };
            println!("Everdark Sovereign? {}", everdark);
        }

    }

    enter_exit!(0, "");
}

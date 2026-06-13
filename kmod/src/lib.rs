use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use elf::ElfBytes;
use elf::abi::{SHN_ABS, SHN_UNDEF};
use elf::endian::NativeEndian;

const KPTR_PATH: &str = "/proc/sys/kernel/kptr_restrict";

struct KptrGuard {
    saved: u8,
    initialized: bool,
}

impl KptrGuard {
    fn open() -> io::Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).open(KPTR_PATH)?;

        let mut buf = [0u8; 1];
        let initialized = if file.read_exact(&mut buf).is_ok() && buf[0] >= b'0' && buf[0] <= b'9' {
            true
        } else {
            false
        };
        let saved = buf[0];

        file.seek(SeekFrom::Start(0))?;
        file.write_all(b"1")?;

        Ok(KptrGuard { saved, initialized })
    }

    fn restore(&self) -> io::Result<()> {
        if !self.initialized {
            return Ok(());
        }
        let mut file = OpenOptions::new().write(true).open(KPTR_PATH)?;
        file.write_all(&[self.saved])?;
        Ok(())
    }
}

impl Drop for KptrGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn normalize_symbol<'a>(sym: &'a str, buf: &'a mut String) -> &'a str {
    buf.clear();
    let dollar_pos = sym.find('$');
    let llvm_pos = sym.find(".llvm.");
    let cut = match (dollar_pos, llvm_pos) {
        (Some(d), Some(l)) => Some(std::cmp::min(d, l)),
        (Some(d), None) => Some(d),
        (None, Some(l)) => Some(l),
        (None, None) => None,
    };
    match cut {
        Some(pos) => {
            buf.push_str(&sym[..pos]);
            buf.as_str()
        }
        None => sym,
    }
}

fn hex_to_u64(s: &str) -> Option<u64> {
    u64::from_str_radix(s, 16).ok()
}

fn parse_kallsyms() -> io::Result<HashMap<String, u64>> {
    let guard = KptrGuard::open()?;
    let content = fs::read_to_string("/proc/kallsyms")?;
    let mut symbols = HashMap::with_capacity(262144);
    let mut buf = String::new();

    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let addr_str = match parts.next() {
            Some(s) => s,
            None => continue,
        };
        let addr = match hex_to_u64(addr_str) {
            Some(a) => a,
            None => continue,
        };
        // skip type
        if parts.next().is_none() {
            continue;
        }
        let name = match parts.next() {
            Some(n) => n,
            None => continue,
        };
        let normalized = normalize_symbol(name, &mut buf);
        symbols.insert(normalized.to_owned(), addr);
    }
    drop(guard);
    Ok(symbols)
}

fn patch_and_load(data: &mut Vec<u8>, ksyms: &HashMap<String, u64>) -> Result<(), String> {
    let modifications = {
        let elf_file = ElfBytes::<NativeEndian>::minimal_parse(data.as_slice())
            .map_err(|e| format!("failed to parse ELF: {}", e))?;

        let (symtab, strtab) = elf_file
            .symbol_table()
            .map_err(|e| format!("failed to get symbol table: {}", e))?
            .ok_or("no symbol table found")?;

        let symtab_header = elf_file
            .section_header_by_name(".symtab")
            .map_err(|e| format!("failed to find .symtab section: {}", e))?
            .ok_or(".symtab section not found")?;

        let symtab_base_offset = symtab_header.sh_offset as usize;
        let sym_entry_size = symtab_header.sh_entsize as usize;

        assert_eq!(sym_entry_size, 24, "unexpected Elf64_Sym size");

        let mut nbuf = String::new();
        let mut mods: Vec<(usize, u64)> = Vec::new();
        let mut missing_symbols = Vec::new();

        for (i, sym) in symtab.iter().enumerate() {
            if sym.st_shndx != SHN_UNDEF || sym.st_name == 0 {
                continue;
            }
            let raw_name = strtab
                .get(sym.st_name as usize)
                .map_err(|e| format!("failed to get symbol name: {}", e))?;
            let name = normalize_symbol(raw_name, &mut nbuf);

            match ksyms.get(name) {
                Some(&addr) => {
                    if addr == 0 {
                        eprintln!("Warning: symbol {} has address 0", name);
                    }
                    eprintln!("Patching symbol {} -> 0x{:x}", name, addr);
                    mods.push((symtab_base_offset + i * sym_entry_size, addr));
                }
                None => {
                    missing_symbols.push(name.to_owned());
                }
            }
        }

        if !missing_symbols.is_empty() {
            return Err(format!("missing symbols: {}", missing_symbols.join(", ")));
        }

        mods
    };

    // Elf64_Sym layout (LE):
    //   +0  st_name  u32
    //   +4  st_info  u8
    //   +5  st_other u8
    //   +6  st_shndx u16
    //   +8  st_value u64
    //   +16 st_size  u64
    for (sym_offset, addr) in modifications {
        let entry = data
            .get_mut(sym_offset..sym_offset + 24)
            .ok_or_else(|| format!("symbol offset {} out of bounds", sym_offset))?;

        entry[6..8].copy_from_slice(&(SHN_ABS as u16).to_le_bytes());
        entry[8..16].copy_from_slice(&addr.to_le_bytes());
    }
    rustix::system::init_module(data, c"").map_err(|e| e.to_string())
}

pub fn load(path: &Path) -> Result<(), String> {
    let ksyms = parse_kallsyms().map_err(|e| format!("parse_kallsyms failed: {}", e))?;
    let mut file = File::open(path).map_err(|e| format!("open {}: {}", path.display(), e))?;
    let metadata = file.metadata().map_err(|e| format!("metadata: {}", e))?;
    let fsz = metadata.len() as usize;
    let mut data = vec![0u8; fsz];
    file.read_exact(&mut data)
        .map_err(|e| format!("read: {}", e))?;
    patch_and_load(&mut data, &ksyms)
}

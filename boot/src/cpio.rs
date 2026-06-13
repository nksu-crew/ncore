use anyhow::{Result, bail};

pub struct CpioEntry {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub data: Vec<u8>,
}

pub fn align4(n: usize) -> usize {
    (n + 3) & !3
}

pub fn hex32(s: &[u8]) -> Result<u32> {
    let s = std::str::from_utf8(s).map_err(|_| anyhow::anyhow!("non-utf8 cpio field"))?;
    u32::from_str_radix(s, 16).map_err(|e| anyhow::anyhow!("hex32 parse '{}': {}", s, e))
}

pub fn parse_cpio(data: &[u8]) -> Result<Vec<CpioEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0usize;

    loop {
        if pos + 110 > data.len() {
            bail!("cpio truncated at offset {}", pos);
        }
        let hdr = &data[pos..pos + 110];
        if &hdr[0..6] != b"070701" && &hdr[0..6] != b"070702" {
            bail!("invalid cpio magic at offset {}", pos);
        }

        let mode = hex32(&hdr[14..22])?;
        let uid = hex32(&hdr[22..30])?;
        let gid = hex32(&hdr[30..38])?;
        let filesize = hex32(&hdr[54..62])? as usize;
        let namesize = hex32(&hdr[94..102])? as usize;

        let name_start = pos + 110;
        let name_end = name_start + namesize;
        if name_end > data.len() {
            bail!("cpio name out of bounds at offset {}", pos);
        }
        // namesize には NUL が含まれる
        let name = std::str::from_utf8(&data[name_start..name_end.saturating_sub(1)])
            .unwrap_or("")
            .to_owned();

        let data_start = align4(name_end);
        let data_end = data_start + filesize;
        if data_end > data.len() {
            bail!("cpio data out of bounds for entry '{}'", name);
        }

        if name == "TRAILER!!!" {
            break;
        }

        entries.push(CpioEntry {
            name,
            mode,
            uid,
            gid,
            data: data[data_start..data_end].to_vec(),
        });

        pos = align4(data_end);
    }

    Ok(entries)
}

pub fn write_cpio(entries: &[CpioEntry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut ino = 300u32;

    for entry in entries {
        write_cpio_entry(
            &mut out,
            ino,
            &entry.name,
            entry.mode,
            entry.uid,
            entry.gid,
            &entry.data,
        );
        ino += 1;
    }
    // trailer
    write_cpio_entry(&mut out, 0, "TRAILER!!!", 0, 0, 0, &[]);
    // trailer の後も 512 バイトアライン（一部ツールが要求）
    let rem = out.len() % 512;
    if rem != 0 {
        out.extend(std::iter::repeat(0u8).take(512 - rem));
    }
    Ok(out)
}

pub fn write_cpio_entry(
    out: &mut Vec<u8>,
    ino: u32,
    name: &str,
    mode: u32,
    uid: u32,
    gid: u32,
    data: &[u8],
) {
    let namesize = name.len() + 1; // NUL 込み
    let filesize = data.len();

    let hdr = format!(
        "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        ino,  // ino
        mode, // mode
        uid,  // uid
        gid,  // gid
        1u32, // nlink
        0u32, // mtime
        filesize as u32,
        0u32, // devmajor
        0u32, // devminor
        0u32, // rdevmajor
        0u32, // rdevminor
        namesize as u32,
        0u32, // check
    );
    assert_eq!(hdr.len(), 110);

    out.extend_from_slice(hdr.as_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(0u8); // NUL

    // header(110) + name(namesize) を 4 バイトアライン
    let after_name = 110 + namesize;
    let pad = align4(after_name) - after_name;
    out.extend(std::iter::repeat(0u8).take(pad));

    out.extend_from_slice(data);

    // data を 4 バイトアライン
    let pad = align4(filesize) - filesize;
    out.extend(std::iter::repeat(0u8).take(pad));
}

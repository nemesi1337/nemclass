//! A single-entry ZIP container, just enough for `.rcnet`.
//!
//! A `.rcnet` file is a ZIP archive holding exactly one entry, `Data.xml`. That
//! is the entire container requirement, so this reads and writes that shape
//! directly rather than taking on a general-purpose zip dependency — which would
//! drag its own serde/time/encoding tree into a crate whose dependency graph is
//! deliberately pinned (see the `serde = "=1.0.219"` note in the workspace
//! manifest).
//!
//! Both stored (method 0) and deflated (method 8) entries are read, because
//! .NET's `ZipArchive` picks between them; writing always deflates.

use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;

use crate::error::{ModelError, Result};

const LOCAL_FILE_HEADER: u32 = 0x0403_4b50;
const CENTRAL_DIR_HEADER: u32 = 0x0201_4b50;
const END_OF_CENTRAL_DIR: u32 = 0x0605_4b50;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATED: u16 = 8;

/// A zip whose uncompressed entry would exceed this is refused rather than
/// allocated. `.rcnet` XML for a very large project is a few megabytes; sixty-four
/// is far past any real file and stops a crafted header from asking for gigabytes.
const MAX_ENTRY_SIZE: u64 = 64 * 1024 * 1024;

fn bad(msg: impl Into<String>) -> ModelError {
    ModelError::DeserializeError(msg.into())
}

fn u16_at(buf: &[u8], off: usize) -> Result<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| bad("truncated zip"))
}

fn u32_at(buf: &[u8], off: usize) -> Result<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| bad("truncated zip"))
}

/// Read the entry named `want` out of a zip archive.
///
/// The central directory is the authority on where entries live — the local
/// headers may carry zeroed sizes with the real values in a trailing data
/// descriptor, which is exactly what a streaming writer like .NET's produces.
pub fn read_entry(archive: &[u8], want: &str) -> Result<Vec<u8>> {
    let eocd = find_eocd(archive).ok_or_else(|| bad("not a zip archive (no end-of-central-directory record)"))?;
    let entry_count = u16_at(archive, eocd + 10)? as usize;
    let cd_offset = u32_at(archive, eocd + 16)? as usize;

    let mut cursor = cd_offset;
    for _ in 0..entry_count {
        if u32_at(archive, cursor)? != CENTRAL_DIR_HEADER {
            return Err(bad("corrupt zip central directory"));
        }
        let method = u16_at(archive, cursor + 10)?;
        let compressed_size = u32_at(archive, cursor + 20)? as usize;
        let uncompressed_size = u32_at(archive, cursor + 24)? as u64;
        let name_len = u16_at(archive, cursor + 28)? as usize;
        let extra_len = u16_at(archive, cursor + 30)? as usize;
        let comment_len = u16_at(archive, cursor + 32)? as usize;
        let local_offset = u32_at(archive, cursor + 42)? as usize;

        let name = archive
            .get(cursor + 46..cursor + 46 + name_len)
            .ok_or_else(|| bad("truncated zip entry name"))?;

        if name == want.as_bytes() {
            if uncompressed_size > MAX_ENTRY_SIZE {
                return Err(bad(format!(
                    "zip entry '{want}' declares {uncompressed_size} bytes, past the {MAX_ENTRY_SIZE}-byte limit"
                )));
            }
            return read_local_entry(
                archive,
                local_offset,
                method,
                compressed_size,
                uncompressed_size as usize,
            );
        }

        cursor += 46 + name_len + extra_len + comment_len;
    }

    Err(bad(format!("zip archive has no '{want}' entry")))
}

fn read_local_entry(
    archive: &[u8],
    offset: usize,
    method: u16,
    compressed_size: usize,
    uncompressed_size: usize,
) -> Result<Vec<u8>> {
    if u32_at(archive, offset)? != LOCAL_FILE_HEADER {
        return Err(bad("corrupt zip local file header"));
    }
    let name_len = u16_at(archive, offset + 26)? as usize;
    let extra_len = u16_at(archive, offset + 28)? as usize;
    let data_start = offset + 30 + name_len + extra_len;
    let data = archive
        .get(data_start..data_start + compressed_size)
        .ok_or_else(|| bad("truncated zip entry data"))?;

    match method {
        METHOD_STORED => Ok(data.to_vec()),
        METHOD_DEFLATED => {
            let mut out = Vec::with_capacity(uncompressed_size);
            DeflateDecoder::new(data)
                // `take` bounds what a lying header can make us allocate; the
                // declared size was already range-checked by the caller.
                .take(MAX_ENTRY_SIZE)
                .read_to_end(&mut out)
                .map_err(|e| bad(format!("zip entry does not inflate: {e}")))?;
            Ok(out)
        }
        other => Err(bad(format!("unsupported zip compression method {other}"))),
    }
}

/// Scan backwards for the end-of-central-directory signature.
///
/// Backwards because the record is last and its position depends on a trailing
/// comment of arbitrary length; forwards scanning could match the signature
/// inside compressed data.
fn find_eocd(archive: &[u8]) -> Option<usize> {
    if archive.len() < 22 {
        return None;
    }
    // The comment is at most 0xFFFF bytes, so the record starts no earlier than
    // that plus its own 22-byte length from the end.
    let earliest = archive.len().saturating_sub(22 + 0xFFFF);
    (earliest..=archive.len() - 22).rev().find(|&i| {
        u32::from_le_bytes([archive[i], archive[i + 1], archive[i + 2], archive[i + 3]])
            == END_OF_CENTRAL_DIR
    })
}

/// Write a zip archive containing exactly one deflated entry.
pub fn write_entry(name: &str, contents: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(contents)
        .map_err(|e| ModelError::SerializeError(format!("deflate failed: {e}")))?;
    let compressed = encoder
        .finish()
        .map_err(|e| ModelError::SerializeError(format!("deflate failed: {e}")))?;

    let crc = crc32(contents);
    let name_bytes = name.as_bytes();
    let mut out = Vec::with_capacity(compressed.len() + 128);

    // Local file header.
    out.extend_from_slice(&LOCAL_FILE_HEADER.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&METHOD_DEFLATED.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // mod time
    out.extend_from_slice(&0u16.to_le_bytes()); // mod date
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    out.extend_from_slice(&(contents.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra len
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(&compressed);

    // Central directory.
    let cd_offset = out.len();
    out.extend_from_slice(&CENTRAL_DIR_HEADER.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes()); // version made by
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&METHOD_DEFLATED.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // mod time
    out.extend_from_slice(&0u16.to_le_bytes()); // mod date
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    out.extend_from_slice(&(contents.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra len
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    out.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    out.extend_from_slice(name_bytes);
    let cd_len = out.len() - cd_offset;

    // End of central directory.
    out.extend_from_slice(&END_OF_CENTRAL_DIR.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
    out.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
    out.extend_from_slice(&1u16.to_le_bytes()); // entries total
    out.extend_from_slice(&(cd_len as u32).to_le_bytes());
    out.extend_from_slice(&(cd_offset as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len

    Ok(out)
}

/// CRC-32 (IEEE), the checksum a zip entry header carries.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_written_entry_reads_back_identically() {
        let payload = b"<reclass>hello</reclass>".repeat(100);
        let archive = write_entry("Data.xml", &payload).unwrap();
        assert_eq!(read_entry(&archive, "Data.xml").unwrap(), payload);
    }

    #[test]
    fn crc32_matches_the_known_check_value() {
        // The IEEE CRC-32 of "123456789" — the standard check value.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn a_missing_entry_is_an_error_not_an_empty_document() {
        let archive = write_entry("Other.xml", b"x").unwrap();
        let Err(e) = read_entry(&archive, "Data.xml") else {
            panic!("reading an absent entry must fail");
        };
        assert!(e.to_string().contains("Data.xml"), "{e}");
    }

    #[test]
    fn a_non_zip_input_is_rejected() {
        assert!(read_entry(b"not a zip file at all", "Data.xml").is_err());
    }
}

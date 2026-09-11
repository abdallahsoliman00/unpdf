//! `unpdf info` reports content missing from the output on its own lines, not only through
//! the quality warning -- `--quiet` silences warnings, and a diagnostic command must not hide
//! a loss because the caller asked for less noise.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_unpdf")
}

/// Wraps 1-indexed object bodies in a header, a cross-reference table and a trailer.
fn assemble(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for offset in &offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<</Size {}/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut out = dict.as_bytes().to_vec();
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\nendstream");
    out
}

/// One page whose content stream and font are given.
fn one_page(content: Vec<u8>, font: &[u8], extra: &[&[u8]]) -> Vec<u8> {
    let mut objects = vec![
        b"<</Type/Catalog/Pages 2 0 R>>".to_vec(),
        b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec(),
        b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]\
          /Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>"
            .to_vec(),
        content,
        font.to_vec(),
    ];
    objects.extend(extra.iter().map(|o| o.to_vec()));
    assemble(&objects)
}

const HELVETICA: &[u8] = b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>";

fn readable_pdf() -> Vec<u8> {
    let content = b"BT /F1 12 Tf 72 720 Td (Hello World) Tj ET";
    one_page(
        stream(&format!("<</Length {}>>", content.len()), content),
        HELVETICA,
        &[],
    )
}

/// The page's only content stream claims `/FlateDecode` over bytes no decoder accepts.
fn undecodable_content_pdf() -> Vec<u8> {
    one_page(
        stream("<</Length 16/Filter/FlateDecode>>", &[0xFF; 16]),
        HELVETICA,
        &[],
    )
}

/// Identity-H composite font with no `ToUnicode` map: the run cannot be decoded.
fn unresolvable_font_pdf() -> Vec<u8> {
    let content = b"BT /F1 12 Tf 72 720 Td (\\001\\102\\001\\103) Tj ET";
    one_page(
        stream(&format!("<</Length {}>>", content.len()), content),
        b"<</Type/Font/Subtype/Type0/BaseFont/NoMap/Encoding/Identity-H/DescendantFonts[6 0 R]>>",
        &[b"<</Type/Font/Subtype/CIDFontType2/BaseFont/NoMap\
            /CIDSystemInfo<</Registry(Adobe)/Ordering(Identity)/Supplement 0>>>>"],
    )
}

/// `unpdf --quiet info <pdf>`'s stdout.
fn quiet_info(name: &str, pdf: &[u8]) -> String {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join(name);
    std::fs::write(&path, pdf).expect("write fixture");
    let out = Command::new(bin())
        .env("NO_COLOR", "1")
        .args(["--quiet", "info"])
        .arg(&path)
        .output()
        .expect("spawn unpdf");
    assert!(out.status.success(), "info failed: {:?}", out);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn info_reports_an_undecodable_content_stream_even_when_quiet() {
    let stdout = quiet_info("undecodable.pdf", &undecodable_content_pdf());
    assert!(stdout.contains("Content streams"), "{stdout}");
    assert!(stdout.contains("1 undecodable, left out"), "{stdout}");
}

#[test]
fn info_reports_unreadable_text_runs_even_when_quiet() {
    let stdout = quiet_info("unresolvable.pdf", &unresolvable_font_pdf());
    assert!(stdout.contains("Text runs"), "{stdout}");
    assert!(stdout.contains("unreadable, dropped"), "{stdout}");
}

/// An intact document must not read a line saying nothing was lost.
#[test]
fn info_prints_neither_loss_line_for_an_intact_document() {
    let stdout = quiet_info("readable.pdf", &readable_pdf());
    assert!(stdout.contains("Pages"), "the command ran: {stdout}");
    assert!(!stdout.contains("Content streams"), "{stdout}");
    assert!(!stdout.contains("Text runs"), "{stdout}");
}

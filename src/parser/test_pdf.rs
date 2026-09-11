//! PDF bytes assembled by the tests themselves, so no unit test depends on a file that can go
//! missing.
//!
//! Tests in this crate used to either load `test-files/*.pdf` through a helper that returned
//! `None` when the file was absent -- and with `test-files/` gitignored and never present, every
//! caller returned early and reported green without executing a single assertion -- or carry
//! their own copy of the same cross-reference-table assembler. A fixture a test assembles cannot
//! go missing, and it says in the test exactly which bytes the behaviour depends on.

/// Wraps `objects` -- numbered from 1, in the order given -- in a header, a cross-reference table
/// and a trailer whose `/Root` is object `root`.
pub(crate) fn pdf(objects: Vec<Vec<u8>>, root: usize) -> Vec<u8> {
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (idx, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", idx + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref_start = out.len();
    let size = objects.len() + 1;
    out.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f \n").as_bytes());
    for offset in &offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<</Size {size}/Root {root} 0 R>>\nstartxref\n{xref_start}\n%%EOF\n")
            .as_bytes(),
    );
    out
}

/// A stream object's body: `dict`, then `data` between `stream` and `endstream`.
pub(crate) fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut out = dict.as_bytes().to_vec();
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\nendstream");
    out
}

/// The text drawn by [`one_page_pdf`]'s content stream.
pub(crate) const ONE_PAGE_CONTENT: &[u8] = b"BT /F1 12 Tf 72 720 Td (Hi) Tj ET";

/// Catalog, page tree, one 595 x 842 page, one content stream ([`ONE_PAGE_CONTENT`]).
pub(crate) fn one_page_pdf() -> Vec<u8> {
    pdf(
        vec![
            b"<</Type/Catalog/Pages 2 0 R>>".to_vec(),
            b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec(),
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Contents 4 0 R>>".to_vec(),
            stream(
                &format!("<</Length {}>>", ONE_PAGE_CONTENT.len()),
                ONE_PAGE_CONTENT,
            ),
        ],
        1,
    )
}

//! A content stream the parser cannot decode is content the page lost, and lenient
//! parsing -- the default -- keeps going without it. That is the point of lenient, but
//! the loss has to be reported: a page whose only content stream failed comes back
//! empty, which otherwise reads exactly like a blank page.

mod common;

use unpdf::parser::ErrorMode;
use unpdf::{parse_bytes_with_options, Document, ParseOptions};

fn lenient(bytes: &[u8]) -> Document {
    parse_bytes_with_options(
        bytes,
        ParseOptions::default().with_error_mode(ErrorMode::Lenient),
    )
    .expect("lenient must not fail the document over an undecodable content stream")
}

/// The more common shape: the page has one content stream, and it is the one that failed.
#[test]
fn a_page_whose_only_content_stream_cannot_be_decoded_reports_it() {
    let doc = lenient(&common::undecodable_content_pdf());

    assert_eq!(doc.pages.len(), 1, "the page is kept, empty");
    assert_eq!(doc.pages[0].undecodable_content_streams, 1);
    assert_eq!(doc.extraction_quality.undecodable_content_streams, 1);
}

#[test]
fn a_content_array_with_one_undecodable_part_reports_it() {
    let doc = lenient(&common::partly_undecodable_content_pdf());

    assert!(
        doc.plain_text().contains("Hello World"),
        "the readable part is kept"
    );
    assert_eq!(doc.pages[0].undecodable_content_streams, 1);
    assert_eq!(doc.extraction_quality.undecodable_content_streams, 1);
}

#[test]
fn undecodable_content_produces_a_warning() {
    let doc = lenient(&common::undecodable_content_pdf());

    let warning = doc
        .extraction_quality
        .warning_message()
        .expect("a document that lost content must warn");
    assert!(
        warning.contains("content stream"),
        "the warning must name what was lost, not guess at causes: {warning:?}"
    );
}

#[test]
fn a_healthy_document_reports_no_undecodable_content() {
    let doc = lenient(&common::text_pdf());

    assert_eq!(doc.pages[0].undecodable_content_streams, 0);
    assert_eq!(doc.extraction_quality.undecodable_content_streams, 0);
}

/// The document total is built from the pages, and the count reaches the JSON the
/// bindings read.
#[test]
fn the_count_is_the_sum_of_its_pages_and_reaches_the_json() {
    let doc = lenient(&common::partly_undecodable_content_pdf());

    let total: usize = doc
        .pages
        .iter()
        .map(|p| p.undecodable_content_streams)
        .sum();
    assert_eq!(total, doc.extraction_quality.undecodable_content_streams);

    let json = serde_json::to_string(&doc.extraction_quality).expect("quality serialises");
    assert!(json.contains("\"undecodable_content_streams\":1"), "{json}");
}

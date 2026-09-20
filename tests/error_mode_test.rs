//! `ErrorMode::Strict` is documented as "fail on any error", and nothing checked it: the
//! default mode is lenient, so the strict path is where a gap can stay hidden. These tests
//! hold both modes against the same damaged documents.

mod common;

use unpdf::parser::ErrorMode;
use unpdf::{parse_bytes_with_options, ParseOptions};

fn with(mode: ErrorMode) -> ParseOptions {
    ParseOptions::default().with_error_mode(mode)
}

/// Control: strict does not fail a document that has nothing wrong with it.
#[test]
fn strict_parses_a_healthy_document() {
    let doc = parse_bytes_with_options(&common::text_pdf(), with(ErrorMode::Strict))
        .expect("a well-formed document must parse under strict");

    assert!(doc.plain_text().contains("Hello World"));
}

#[test]
fn strict_fails_on_an_undecodable_content_stream() {
    let result =
        parse_bytes_with_options(&common::undecodable_content_pdf(), with(ErrorMode::Strict));

    assert!(result.is_err(), "strict parsed a page it could not decode");
}

#[test]
fn lenient_keeps_a_document_whose_content_stream_cannot_be_decoded() {
    parse_bytes_with_options(&common::undecodable_content_pdf(), with(ErrorMode::Lenient))
        .expect("lenient must not fail the document over one undecodable page");
}

/// A page's content may be split across several streams. One of them failing to decode is
/// the same damage as a single stream failing -- strict must not drop that part and report
/// the rest as a complete page.
#[test]
fn strict_fails_when_one_part_of_a_content_array_cannot_be_decoded() {
    match parse_bytes_with_options(
        &common::partly_undecodable_content_pdf(),
        with(ErrorMode::Strict),
    ) {
        Err(_) => {}
        Ok(doc) => panic!(
            "strict parsed a page with an undecodable content part as complete: {:?}",
            doc.plain_text()
        ),
    }
}

/// Lenient keeps what it can read: the other part of the same page.
#[test]
fn lenient_keeps_the_readable_part_of_a_content_array() {
    let doc = parse_bytes_with_options(
        &common::partly_undecodable_content_pdf(),
        with(ErrorMode::Lenient),
    )
    .expect("lenient must not fail the document over one undecodable content part");

    assert!(doc.plain_text().contains("Hello World"));
}

/// `/Contents` is optional: a page without it is a legal, empty page (form fields and
/// annotations only, say). Nothing was lost, so strict has nothing to fail.
#[test]
fn strict_parses_a_page_that_has_no_content_stream() {
    let doc = parse_bytes_with_options(&common::form_pdf(), with(ErrorMode::Strict))
        .expect("a page without /Contents is well-formed");

    assert_eq!(doc.pages.len(), 1);
    assert_eq!(doc.pages[0].undecodable_content_streams, 0);
}

/// Lenient must not count the absence as a loss either.
#[test]
fn lenient_reports_no_loss_for_a_page_that_has_no_content_stream() {
    let doc = parse_bytes_with_options(&common::form_pdf(), with(ErrorMode::Lenient))
        .expect("a page without /Contents is well-formed");

    assert_eq!(doc.extraction_quality.undecodable_content_streams, 0);
    let warning = doc.extraction_quality.warning_message().unwrap_or_default();
    assert!(!warning.contains("content stream"), "{warning}");
}

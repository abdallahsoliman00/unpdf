mod common;

use unpdf::{parse_bytes, ExtractionQuality};

#[test]
fn test_extraction_quality_from_text() {
    let q = ExtractionQuality::from_text("The quick brown fox jumps over the lazy dog");
    assert_eq!(q.char_count, 43);
    assert_eq!(q.word_count, 9);
    assert_eq!(q.replacement_char_count, 0);
    assert!(q.is_good());
    assert!(q.warning_message().is_none());
}

#[test]
fn test_extraction_quality_low() {
    // 3 replacement chars + 2 normal chars = 5 total, ratio = 0.6
    let q = ExtractionQuality::from_text("\u{FFFD}\u{FFFD}\u{FFFD}ab");
    assert_eq!(q.char_count, 5);
    assert_eq!(q.replacement_char_count, 3);
    assert!(!q.is_good());
    let msg = q.warning_message().unwrap();
    assert!(msg.contains("3 of 5"));
}

#[test]
fn test_extraction_quality_empty() {
    let q = ExtractionQuality::from_text("");
    assert_eq!(q.char_count, 0);
    assert_eq!(q.word_count, 0);
    assert!(!q.is_good());
    assert!(q.warning_message().is_some());
}

/// A page with a text layer reports that text in the quality metrics, cleanly.
#[test]
fn a_text_page_reports_its_words_and_no_replacement_characters() {
    let q = parse_bytes(&common::text_pdf()).unwrap().extraction_quality;
    assert_eq!(q.word_count, 2, "\"Hello World\" is two words");
    assert_eq!(q.replacement_char_count, 0);
    assert!(q.is_good(), "got {:?}", q.warning_message());
}

/// A document that is only an image has no text layer to extract. The report must say so,
/// and say it in terms a reader can act on.
#[test]
fn an_image_only_document_is_reported_as_a_scan() {
    let q = parse_bytes(&common::image_only_pdf())
        .unwrap()
        .extraction_quality;
    assert!(q.is_scan_pdf);
    assert_eq!(q.char_count, 0);
    let warning = q.warning_message().expect("a scan must warn");
    assert!(
        warning.contains("scanned image"),
        "the warning should name the cause, got {warning:?}"
    );
}

#[test]
fn test_toc_dot_leader_removal() {
    use unpdf::render::{CleanupPipeline, CleanupPreset};
    let pipeline = CleanupPipeline::from_preset(CleanupPreset::Standard);
    let input = "Chapter 1: Introduction ................................ 6\n\
                 Chapter 2: Methods ...................................... 12\n\
                 Normal paragraph text without dots.";
    let output = pipeline.process(input);
    assert!(
        !output.contains("................................"),
        "Dot leaders should be removed"
    );
    assert!(output.contains("Introduction"));
    assert!(output.contains("Normal paragraph text"));
}

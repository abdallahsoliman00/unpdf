//! Integration tests for U-9 STEP 2: VLM image understanding wiring (points A/B).
//!
//! Exercises `PdfParser::parse` end-to-end against a local mock AI endpoint —
//! `unpdf` never talks to a real model here.

mod common;

use common::mock_ai::MockServer;
use common::{image_only_jpeg_pdf, repeated_logo_pdf, text_pdf, text_with_inline_image_pdf};
use unparser_shared::ai::{AiConfig, ImageScope};
use unpdf::{parse_bytes_with_options, Block, ParseOptions, RenderOptions};

fn config(url: &str) -> AiConfig {
    let mut cfg = AiConfig::new(url, "test-key", "test-model");
    cfg.max_retries = 1; // keep failure-path tests fast — no backoff sleep
    cfg.timeout = std::time::Duration::from_secs(5); // fail fast instead of the 120s default
    cfg
}

fn chat_response(content: &str) -> String {
    serde_json::json!({
        "choices": [{
            "message": {"content": content},
            "finish_reason": "stop",
        }]
    })
    .to_string()
}

fn structured_body() -> String {
    serde_json::json!({
        "kind": "structured",
        "blocks": [
            {"type": "paragraph", "text": "Scanned title"},
            {
                "type": "table",
                "header_rows": 1,
                "rows": [
                    [{"text": "A", "rowspan": 1, "colspan": 1}, {"text": "B", "rowspan": 1, "colspan": 2}],
                    [{"text": "1", "rowspan": 1, "colspan": 1}, {"text": "2", "rowspan": 1, "colspan": 1}]
                ]
            }
        ]
    })
    .to_string()
}

fn description_body(text: &str) -> String {
    serde_json::json!({"kind": "description", "text": text}).to_string()
}

// --- Point A: OCR-suppressed / text-less single-image pages ---------------------

#[test]
fn point_a_structured_response_replaces_the_image_only_page() {
    let server = MockServer::serving(vec![(200, chat_response(&structured_body()))]);
    let options = ParseOptions::new()
        .with_resources(true)
        .with_min_image_dimension(0)
        .with_ai(config(server.url()));

    let doc = parse_bytes_with_options(&image_only_jpeg_pdf(), options).unwrap();

    assert_eq!(doc.pages.len(), 1);
    let elements = &doc.pages[0].elements;
    assert!(
        !elements.iter().any(|b| matches!(b, Block::Image { .. })),
        "structured mapping must replace the image block, got {elements:?}"
    );
    let Block::Paragraph(p) = &elements[0] else {
        panic!("expected a paragraph first, got {:?}", elements[0]);
    };
    assert_eq!(p.plain_text(), "Scanned title");
    let Block::Table(t) = &elements[1] else {
        panic!("expected a table second, got {:?}", elements[1]);
    };
    assert_eq!(t.header_rows, 1);
    assert_eq!(t.rows[0].cells[1].colspan, 2);
    assert_eq!(doc.extraction_quality.ai_fallback_count, 0);
}

#[test]
fn point_a_description_response_fills_alt_text() {
    let server = MockServer::serving(vec![(
        200,
        chat_response(&description_body("a photo of a cat")),
    )]);
    let options = ParseOptions::new()
        .with_resources(true)
        .with_min_image_dimension(0)
        .with_ai(config(server.url()));

    let doc = parse_bytes_with_options(&image_only_jpeg_pdf(), options).unwrap();

    let elements = &doc.pages[0].elements;
    assert_eq!(elements.len(), 1);
    let Block::Image { alt_text, .. } = &elements[0] else {
        panic!("expected the image block to survive, got {:?}", elements[0]);
    };
    assert_eq!(alt_text.as_deref(), Some("a photo of a cat"));
    assert_eq!(doc.extraction_quality.ai_fallback_count, 0);
}

#[test]
fn point_a_failure_leaves_the_page_unchanged_and_counts_a_fallback() {
    let server = MockServer::serving(vec![(500, "internal error".to_string())]);
    let options = ParseOptions::new()
        .with_resources(true)
        .with_min_image_dimension(0)
        .with_ai(config(server.url()));

    let doc = parse_bytes_with_options(&image_only_jpeg_pdf(), options).unwrap();

    let elements = &doc.pages[0].elements;
    assert_eq!(elements.len(), 1);
    let Block::Image { alt_text, .. } = &elements[0] else {
        panic!("expected the original image block, got {:?}", elements[0]);
    };
    assert!(alt_text.is_none());
    assert_eq!(doc.extraction_quality.ai_fallback_count, 1);
}

#[test]
fn ai_none_never_contacts_the_endpoint() {
    // No AiConfig at all — parsing must behave exactly as before U-9, and nothing
    // here even starts a mock server to prove it can't be reached.
    let doc = parse_bytes_with_options(
        &image_only_jpeg_pdf(),
        ParseOptions::new()
            .with_resources(true)
            .with_min_image_dimension(0),
    )
    .unwrap();
    let elements = &doc.pages[0].elements;
    assert_eq!(elements.len(), 1);
    assert!(matches!(elements[0], Block::Image { .. }));
    assert_eq!(doc.extraction_quality.ai_fallback_count, 0);
}

#[test]
fn resource_bytes_are_forced_then_stripped_when_extract_resources_was_not_requested() {
    let server = MockServer::serving(vec![(200, chat_response(&description_body("x")))]);
    // Deliberately NOT calling .with_resources(true) — ai alone must still get
    // image bytes internally, but the caller never asked for the inventory back.
    let options = ParseOptions::new()
        .with_min_image_dimension(0)
        .with_ai(config(server.url()));

    let doc = parse_bytes_with_options(&image_only_jpeg_pdf(), options).unwrap();

    assert!(
        doc.pages[0].images.is_empty(),
        "extract_resources was never requested — the resource inventory must stay empty"
    );
    let Block::Image { alt_text, .. } = &doc.pages[0].elements[0] else {
        panic!("expected the image block");
    };
    assert_eq!(
        alt_text.as_deref(),
        Some("x"),
        "the AI result itself must still land even though resources were stripped"
    );
}

// --- AI refine (render path) ----------------------------------------------------

#[test]
fn ai_refine_replaces_the_rendered_markdown() {
    let server = MockServer::serving(vec![(200, chat_response("# Rewritten\n\nBy the model."))]);
    let doc = parse_bytes_with_options(&text_pdf(), ParseOptions::new()).unwrap();

    let markdown = unpdf::render::to_markdown(
        &doc,
        &RenderOptions::new().with_ai_refine(config(server.url())),
    )
    .unwrap();

    assert_eq!(markdown, "# Rewritten\n\nBy the model.");
}

#[test]
fn ai_refine_failure_keeps_the_un_refined_markdown() {
    let server = MockServer::serving(vec![(500, "internal error".to_string())]);
    let doc = parse_bytes_with_options(&text_pdf(), ParseOptions::new()).unwrap();

    let plain = unpdf::render::to_markdown(&doc, &RenderOptions::new()).unwrap();
    let with_failed_ai = unpdf::render::to_markdown(
        &doc,
        &RenderOptions::new().with_ai_refine(config(server.url())),
    )
    .unwrap();

    assert_eq!(
        with_failed_ai, plain,
        "a failed AI refine must leave the rendered markdown untouched"
    );
    assert!(with_failed_ai.contains("Hello World"));
}

// --- Point B: individual images on otherwise-text pages -------------------------

#[test]
fn point_b_fills_alt_text_and_sends_surrounding_paragraph_as_context() {
    let server = MockServer::serving(vec![(200, chat_response(&description_body("a diagram")))]);
    let options = ParseOptions::new()
        .with_resources(true)
        .with_min_image_dimension(0)
        .with_ai(config(server.url()));

    let doc = parse_bytes_with_options(&text_with_inline_image_pdf(), options).unwrap();

    let elements = &doc.pages[0].elements;
    let image = elements
        .iter()
        .find(|b| matches!(b, Block::Image { .. }))
        .expect("image block must survive point B (Description branch)");
    let Block::Image { alt_text, .. } = image else {
        unreachable!()
    };
    assert_eq!(alt_text.as_deref(), Some("a diagram"));

    // `unpdf` currently appends every page's images after its text blocks (see
    // parse_single_page), so the image's nearest preceding paragraph in element
    // order is the page's *last* paragraph, not necessarily its visual neighbour.
    let bodies = server.received_bodies();
    assert_eq!(bodies.len(), 1);
    assert!(
        bodies[0].contains("Second paragraph after the image."),
        "expected the preceding-paragraph context in the request body, got {}",
        bodies[0]
    );
}

#[test]
fn low_confidence_pages_only_skips_point_b_entirely() {
    // No responses queued — a request arriving here would go unanswered until the
    // client's own timeout, so the assertions below are backed by both the untouched
    // alt_text and the absence of any recorded request body.
    let server = MockServer::serving(vec![]);
    let mut cfg = config(server.url());
    cfg.image_scope = ImageScope::LowConfidencePagesOnly;
    let options = ParseOptions::new()
        .with_resources(true)
        .with_min_image_dimension(0)
        .with_ai(cfg);

    let doc = parse_bytes_with_options(&text_with_inline_image_pdf(), options).unwrap();

    let Block::Image { alt_text, .. } = doc.pages[0]
        .elements
        .iter()
        .find(|b| matches!(b, Block::Image { .. }))
        .expect("image block present")
    else {
        unreachable!()
    };
    assert!(alt_text.is_none(), "point B must not have run");
    assert_eq!(doc.extraction_quality.ai_fallback_count, 0);
    assert!(
        server.received_bodies().is_empty(),
        "LowConfidencePagesOnly must not send any request for a text page's images"
    );
}

#[test]
fn a_shared_image_is_captioned_on_every_page_that_draws_it() {
    // Deduplication leaves the bytes on the first page that used them, so a later page's image
    // block references a resource its own `page.images` no longer holds. Resolving against the
    // page alone finds nothing and skips the image in silence -- no error, no fallback count,
    // just a caption that never appears. This is the test that says so out loud.
    let pages = 3;
    let server = MockServer::serving(
        (0..pages)
            .map(|_| (200, chat_response(&description_body("the company logo"))))
            .collect(),
    );
    let options = ParseOptions::new()
        .with_resources(true)
        .with_ai(config(server.url()));

    let doc = parse_bytes_with_options(&repeated_logo_pdf(pages), options).unwrap();

    // One picture in, one picture out -- the deduplication is still doing its job.
    let surviving: std::collections::HashSet<&str> = doc
        .pages
        .iter()
        .flat_map(|p| p.images.iter())
        .map(|(id, _)| id.as_str())
        .collect();
    assert_eq!(
        surviving.len(),
        1,
        "one shared image should be one resource"
    );

    for page in &doc.pages {
        let image = page
            .elements
            .iter()
            .find(|b| matches!(b, Block::Image { .. }))
            .unwrap_or_else(|| panic!("page {} lost its image block", page.number));
        let Block::Image { alt_text, .. } = image else {
            unreachable!()
        };
        assert_eq!(
            alt_text.as_deref(),
            Some("the company logo"),
            "page {} was skipped because its resource lives on another page now",
            page.number
        );
    }
}

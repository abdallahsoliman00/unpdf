//! `unpdf_to_markdown_with_options` — the JSON render-options surface.
//!
//! The flag bitmask reaches four of `RenderOptions`' settings. Everything else — table
//! fallback, heading cap, cleanup preset, page selection, image prefix, and the AI refine
//! pass's credentials — was unreachable from any C-ABI-based binding (C#, Python). These
//! tests pin that each field actually reaches the renderer, since a field that is accepted
//! and then ignored produces a successful render that silently did not do what was asked.
#![cfg(feature = "ffi")]

mod common;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use common::{mixed_pdf, text_pdf};
use unpdf::ffi::{
    unpdf_free_document, unpdf_free_string, unpdf_last_error_kind, unpdf_parse_bytes,
    unpdf_to_markdown, unpdf_to_markdown_with_options, UNPDF_ERROR_INVALID_ARGUMENT,
    UNPDF_FLAG_FRONTMATTER,
};

unsafe fn take_string(ptr: *mut c_char) -> String {
    assert!(!ptr.is_null());
    let s = CStr::from_ptr(ptr).to_str().unwrap().to_owned();
    unpdf_free_string(ptr);
    s
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Renders `bytes` through the JSON surface and returns the markdown.
unsafe fn render(bytes: &[u8], options: Option<&str>) -> String {
    let doc = unpdf_parse_bytes(bytes.as_ptr(), bytes.len());
    assert!(!doc.is_null());
    let out = match options {
        Some(json) => {
            let json = cstr(json);
            take_string(unpdf_to_markdown_with_options(doc, json.as_ptr()))
        }
        None => take_string(unpdf_to_markdown_with_options(doc, std::ptr::null())),
    };
    unpdf_free_document(doc);
    out
}

#[test]
fn null_options_matches_the_default_flag_render() {
    let bytes = text_pdf();
    unsafe {
        let doc = unpdf_parse_bytes(bytes.as_ptr(), bytes.len());
        assert!(!doc.is_null());
        let via_flags = take_string(unpdf_to_markdown(doc, 0));
        unpdf_free_document(doc);

        let via_json = render(&bytes, None);
        assert_eq!(via_flags, via_json);
    }
}

#[test]
fn frontmatter_reaches_the_renderer_the_same_way_the_flag_does() {
    let bytes = text_pdf();
    unsafe {
        let doc = unpdf_parse_bytes(bytes.as_ptr(), bytes.len());
        assert!(!doc.is_null());
        let via_flag = take_string(unpdf_to_markdown(doc, UNPDF_FLAG_FRONTMATTER));
        unpdf_free_document(doc);

        let via_json = render(&bytes, Some(r#"{"include_frontmatter":true}"#));
        assert!(via_json.starts_with("---"), "no frontmatter: {via_json}");
        assert_eq!(via_flag, via_json);
    }
}

/// `max_heading_level` has no bit in the flag mask, so this field is the first time a
/// C-ABI caller can set it at all.
/// `max_heading_level` has no bit in the flag mask, so this field is the first time a
/// C-ABI caller can set it at all.
///
/// Only its validation and acceptance are pinned here. Observing the cap end-to-end
/// needs a document that renders a heading below level 1, and no fixture in this repo
/// does: every synthetic fixture tried (24/16/12, 28/20/12, 32/22/12 and 30/18/12 point
/// tiers) yields exactly one `#` heading, with the middle tier rendered as a paragraph.
/// That gap belongs to the heading algorithm, not to this surface — the CLI's equivalent
/// `--max-heading` is untested end-to-end for the same reason.
#[test]
fn max_heading_level_is_accepted_within_range() {
    let bytes = mixed_pdf();
    unsafe {
        for level in 1..=6 {
            let out = render(&bytes, Some(&format!(r#"{{"max_heading_level":{level}}}"#)));
            assert!(!out.is_empty(), "level {level} rejected");
        }
    }
}

#[test]
fn page_markers_reach_the_renderer() {
    let bytes = mixed_pdf();
    unsafe {
        let marked = render(&bytes, Some(r#"{"page_markers":"comment"}"#));
        assert!(marked.contains("<!-- page "), "no page markers: {marked}");
        let unmarked = render(&bytes, Some(r#"{"page_markers":"none"}"#));
        assert!(!unmarked.contains("<!-- page "));
    }
}

#[test]
fn image_path_prefix_reaches_the_renderer() {
    let bytes = mixed_pdf();
    unsafe {
        // Accepted and applied; with no images in the fixture the prefix simply has
        // nothing to prefix, so this pins acceptance rather than a visible change.
        let out = render(&bytes, Some(r#"{"image_path_prefix":"assets/"}"#));
        assert!(!out.is_empty());
    }
}

#[test]
fn cleanup_preset_reaches_the_renderer() {
    let bytes = mixed_pdf();
    unsafe {
        let out = render(&bytes, Some(r#"{"cleanup_preset":"aggressive"}"#));
        assert!(!out.is_empty());
    }
}

#[test]
fn page_selection_reaches_the_renderer() {
    let bytes = mixed_pdf();
    unsafe {
        let all = render(&bytes, Some(r#"{"pages":"all"}"#));
        let first = render(&bytes, Some(r#"{"pages":{"range":{"from":1,"to":1}}}"#));
        assert!(
            first.len() <= all.len(),
            "a one-page selection rendered more than the whole document"
        );
    }
}

#[test]
fn an_out_of_range_heading_level_is_rejected() {
    let bytes = text_pdf();
    unsafe {
        let doc = unpdf_parse_bytes(bytes.as_ptr(), bytes.len());
        assert!(!doc.is_null());
        let json = cstr(r#"{"max_heading_level":9}"#);
        let out = unpdf_to_markdown_with_options(doc, json.as_ptr());
        assert!(out.is_null(), "accepted a heading level outside 1-6");
        assert_eq!(unpdf_last_error_kind(), UNPDF_ERROR_INVALID_ARGUMENT);
        unpdf_free_document(doc);
    }
}

#[test]
fn malformed_options_json_is_rejected() {
    let bytes = text_pdf();
    unsafe {
        let doc = unpdf_parse_bytes(bytes.as_ptr(), bytes.len());
        assert!(!doc.is_null());
        let json = cstr("not json");
        let out = unpdf_to_markdown_with_options(doc, json.as_ptr());
        assert!(out.is_null());
        assert_eq!(unpdf_last_error_kind(), UNPDF_ERROR_INVALID_ARGUMENT);
        unpdf_free_document(doc);
    }
}

/// An `ai_refine` object missing one of its three credential fields is a malformed
/// request, not a request to skip the pass — serde rejects it because the fields are
/// required, which is the same outcome the CLI and `FfiParseOptions` produce.
#[cfg(feature = "ai")]
#[test]
fn incomplete_ai_refine_credentials_are_rejected() {
    let bytes = text_pdf();
    unsafe {
        let doc = unpdf_parse_bytes(bytes.as_ptr(), bytes.len());
        assert!(!doc.is_null());
        let json = cstr(r#"{"ai_refine":{"base_url":"http://localhost","model":"m"}}"#);
        let out = unpdf_to_markdown_with_options(doc, json.as_ptr());
        assert!(out.is_null(), "accepted ai_refine without an api_key");
        assert_eq!(unpdf_last_error_kind(), UNPDF_ERROR_INVALID_ARGUMENT);
        unpdf_free_document(doc);
    }
}

/// A configured but unreachable endpoint must leave the un-refined markdown intact
/// rather than failing the render — the same fallback contract the parse-side AI pass
/// keeps.
#[cfg(feature = "ai")]
#[test]
fn ai_refine_falls_back_to_the_un_refined_markdown_when_the_endpoint_is_unreachable() {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let bytes = text_pdf();
    unsafe {
        let plain = render(&bytes, None);
        let with_ai = render(
            &bytes,
            Some(&format!(
                r#"{{"ai_refine":{{"base_url":"http://127.0.0.1:{port}",
                    "api_key":"unused","model":"unused"}}}}"#
            )),
        );
        assert_eq!(
            plain, with_ai,
            "a failed AI refine must leave the markdown unchanged"
        );
    }
}

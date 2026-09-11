mod common;

use unpdf::model::{FieldType, FieldValue, FormField};

#[test]
fn test_form_field_text() {
    let field = FormField {
        name: "FirstName".to_string(),
        field_type: FieldType::Text,
        value: Some(FieldValue::Text("John".to_string())),
        default_value: None,
    };
    assert_eq!(field.display_value(), "John");
}

#[test]
fn test_form_field_checkbox_checked() {
    let field = FormField {
        name: "Agree".to_string(),
        field_type: FieldType::Checkbox,
        value: Some(FieldValue::Boolean(true)),
        default_value: None,
    };
    assert_eq!(field.display_value(), "[x]");
}

#[test]
fn test_form_field_checkbox_unchecked() {
    let field = FormField {
        name: "Agree".to_string(),
        field_type: FieldType::Checkbox,
        value: Some(FieldValue::Boolean(false)),
        default_value: None,
    };
    assert_eq!(field.display_value(), "[ ]");
}

#[test]
fn test_form_field_no_value_uses_default() {
    let field = FormField {
        name: "Email".to_string(),
        field_type: FieldType::Text,
        value: None,
        default_value: Some(FieldValue::Text("default@example.com".to_string())),
    };
    assert_eq!(field.display_value(), "default@example.com");
}

#[test]
fn test_form_field_no_value_no_default() {
    let field = FormField {
        name: "Empty".to_string(),
        field_type: FieldType::Text,
        value: None,
        default_value: None,
    };
    assert_eq!(field.display_value(), "");
}

/// A document with no AcroForm has no form fields -- not an empty placeholder entry.
#[test]
fn a_document_without_a_form_has_no_form_fields() {
    let doc = unpdf::parse_bytes(&common::text_pdf()).unwrap();
    assert!(doc.form_fields.is_empty(), "got {:?}", doc.form_fields);
}

/// Form fields are rendered as a section of their own after the page content, carrying each
/// field's name and value.
#[test]
fn form_fields_are_rendered_as_their_own_markdown_section() {
    let doc = unpdf::parse_bytes(&common::form_pdf()).unwrap();
    let md = unpdf::render::to_markdown(&doc, &unpdf::RenderOptions::default()).unwrap();
    let section = md
        .split("## Form Fields")
        .nth(1)
        .unwrap_or_else(|| panic!("a document with fields gets the section, got {md:?}"));
    assert!(
        section.contains("FirstName") && section.contains("John"),
        "the section should carry the field's name and value, got {section:?}"
    );
}

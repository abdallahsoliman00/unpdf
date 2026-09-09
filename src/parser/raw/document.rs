//! PDF document structure.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::error::{Error, Result};

use super::crypt::{self, EncryptionParams};
use super::stream;
use super::tokenizer::{self, dict_get, PdfDict, PdfObject, PdfStream};
use super::xref::{self, XrefEntry};

/// A parsed PDF document.
pub struct RawDocument {
    /// All loaded objects, keyed by (object_number, generation_number).
    objects: HashMap<(u32, u16), PdfObject>,
    /// The trailer dictionary (from the newest xref section).
    trailer: PdfDict,
    /// PDF version string (e.g., "1.4", "1.7").
    pub version: String,
    /// Objects the xref table pointed at that could not be loaded.
    skipped_objects: usize,
}

/// Result of walking the page tree: the pages found, and what the walk had to drop.
#[derive(Debug, Default, Clone)]
pub struct PageTreeScan {
    /// 1-based page number → object id.
    pub pages: BTreeMap<u32, (u32, u16)>,

    /// Page-tree nodes the walk could not use: an unresolvable reference, a kid that
    /// is not a reference, a node that is neither `/Page` nor `/Pages`, or a missing
    /// catalog / root `Pages` entry.
    ///
    /// This is **not** a count of lost pages — an unusable intermediate `Pages` node
    /// drops its entire subtree, so one unresolved node can cost many pages. Treat any
    /// non-zero value as "the page set is incomplete" and nothing more.
    pub unresolved_nodes: usize,
}

impl RawDocument {
    /// Load a PDF document from bytes.
    pub fn load(data: &[u8]) -> Result<Self> {
        // 1. Parse PDF version from header: %PDF-X.Y
        let version = parse_version(data)?;

        // 2. Parse xref chain to get table + trailer
        let (xref_table, trailer) = xref::parse_xref_chain(data)?;

        // 3. Load all objects from xref entries
        let mut objects = HashMap::new();
        let mut skipped_objects = 0usize;

        // First pass: load all uncompressed objects
        for (&(obj_num, gen_num), &entry) in &xref_table.entries {
            if let XrefEntry::Uncompressed(offset) = entry {
                match tokenizer::parse_object(data, offset) {
                    Ok((obj, _)) => {
                        objects.insert((obj_num, gen_num), obj);
                    }
                    Err(_) => {
                        // Skip objects that fail to parse (e.g., corrupted), but count
                        // them: a caller has no other way to learn the file was lossy.
                        skipped_objects += 1;
                    }
                }
            }
        }

        // Collect compressed xref entries for later ObjStm extraction
        let mut compressed_groups: HashMap<u32, Vec<(u32, u16, u32)>> = HashMap::new();
        for (&(obj_num, gen_num), &entry) in &xref_table.entries {
            if let XrefEntry::Compressed(stream_obj, index) = entry {
                compressed_groups
                    .entry(stream_obj)
                    .or_default()
                    .push((obj_num, gen_num, index));
            }
        }

        let mut doc = RawDocument {
            objects,
            trailer,
            version,
            skipped_objects,
        };

        // Decrypt before ObjStm extraction: ObjStm streams are encrypted and must
        // be decrypted before their compressed content can be decompressed and parsed.
        if doc.is_encrypted() {
            doc.try_decrypt()?;
        }

        // Second pass: extract compressed objects from ObjStm streams (now decrypted).
        // An unusable ObjStm loses every object it carried, so count the whole group —
        // that is the difference between "one object skipped" and "a chapter missing".
        for (stream_obj_num, entries) in &compressed_groups {
            let extracted = doc
                .objects
                .get(&(*stream_obj_num, 0))
                .and_then(|obj| obj.as_stream())
                .and_then(|pdf_stream| extract_objstm_objects(pdf_stream).ok());

            let Some(extracted) = extracted else {
                doc.skipped_objects += entries.len();
                continue;
            };

            for &(obj_num, gen_num, index) in entries {
                match extracted.get(&(index as usize)) {
                    Some(obj) => {
                        doc.objects.insert((obj_num, gen_num), obj.clone());
                    }
                    None => doc.skipped_objects += 1,
                }
            }
        }

        Ok(doc)
    }

    /// Attempt decryption with an empty user password (covers owner-password-only PDFs).
    fn try_decrypt(&mut self) -> Result<()> {
        let params = match self.encryption_params() {
            Some(p) => p,
            None => {
                return Err(Error::PdfParse(
                    "Encrypt dictionary present but could not be parsed".into(),
                ));
            }
        };

        // R2-R4 only: RC4 and AES-128. AES-256 (AESV3, revisions 5 and 6) is not implemented.
        //
        // Reported as `UnsupportedVersion` rather than the catch-all: this is exactly the case
        // that discriminant names, it is already public on all three binding surfaces, and a
        // caller meeting an AES-256 document otherwise cannot tell "this build does not do that
        // yet" apart from any other failure.
        if params.revision > 4 || params.revision < 2 {
            return Err(Error::UnsupportedVersion(format!(
                "encryption revision {}",
                params.revision
            )));
        }

        // Try empty password (most common case: owner-password-only)
        let key = crypt::authenticate_user_password(&params, b"").ok_or(Error::Encrypted)?;

        // Decrypt all objects (except the Encrypt dict itself)
        let encrypt_obj_id = dict_get(&self.trailer, b"Encrypt").and_then(|o| o.as_reference());
        self.decrypt_objects(&key, &params, encrypt_obj_id);

        Ok(())
    }

    /// Decrypt all string and stream objects in the document.
    fn decrypt_objects(
        &mut self,
        file_key: &[u8],
        params: &EncryptionParams,
        encrypt_obj_id: Option<(u32, u16)>,
    ) {
        let obj_ids: Vec<(u32, u16)> = self.objects.keys().cloned().collect();

        for (obj_num, gen_num) in obj_ids {
            // Skip the Encrypt dictionary object itself
            if Some((obj_num, gen_num)) == encrypt_obj_id {
                continue;
            }

            let obj_key = crypt::object_key(file_key, obj_num, gen_num, params.use_aes);

            if let Some(obj) = self.objects.get_mut(&(obj_num, gen_num)) {
                decrypt_object(obj, &obj_key, params.use_aes);
            }
        }
    }

    /// Parse encryption parameters from the trailer /Encrypt dictionary.
    fn encryption_params(&self) -> Option<EncryptionParams> {
        let encrypt_ref = dict_get(&self.trailer, b"Encrypt")?.as_reference()?;
        let encrypt_dict = self.get_dict(encrypt_ref).ok()?;

        let v = dict_get(encrypt_dict, b"V")
            .and_then(|o| o.as_i64())
            .unwrap_or(0) as u32;
        let r = dict_get(encrypt_dict, b"R")
            .and_then(|o| o.as_i64())
            .unwrap_or(0) as u32;
        let length = dict_get(encrypt_dict, b"Length")
            .and_then(|o| o.as_i64())
            .unwrap_or(40) as u32;
        let p = dict_get(encrypt_dict, b"P")
            .and_then(|o| o.as_i64())
            .unwrap_or(0) as i32;

        let o = dict_get(encrypt_dict, b"O")
            .and_then(|o| o.as_str_bytes())?
            .to_vec();
        let u = dict_get(encrypt_dict, b"U")
            .and_then(|o| o.as_str_bytes())?
            .to_vec();

        // Get file ID from trailer /ID array
        let file_id = dict_get(&self.trailer, b"ID")
            .and_then(|o| o.as_array())
            .and_then(|arr| arr.first())
            .and_then(|o| o.as_str_bytes())
            .unwrap_or(&[])
            .to_vec();

        // /EncryptMetadata defaults to true when absent (PDF spec)
        let encrypt_metadata = dict_get(encrypt_dict, b"EncryptMetadata")
            .map(|o| !matches!(o, crate::parser::raw::tokenizer::PdfObject::Bool(false)))
            .unwrap_or(true);

        // Detect AES usage: R4 with /StmF or /StrF = /AESV2
        let use_aes = if r >= 4 {
            let cf = dict_get(encrypt_dict, b"CF").and_then(|o| o.as_dict());
            let stmf = dict_get(encrypt_dict, b"StmF").and_then(|o| o.as_name());
            let strf = dict_get(encrypt_dict, b"StrF").and_then(|o| o.as_name());

            // Check if the named crypt filter uses AESV2
            let filter_name = stmf.or(strf);
            if let (Some(cf_dict), Some(name)) = (cf, filter_name) {
                dict_get(cf_dict, name)
                    .and_then(|o| o.as_dict())
                    .and_then(|d| dict_get(d, b"CFM"))
                    .and_then(|o| o.as_name())
                    .map(|n| n == b"AESV2")
                    .unwrap_or(false)
            } else {
                false
            }
        } else {
            false
        };

        Some(EncryptionParams {
            version: v,
            revision: r,
            key_length: length,
            owner_hash: o,
            user_hash: u,
            permissions: p,
            file_id,
            use_aes,
            encrypt_metadata,
        })
    }

    /// Get an object by its ID (object_number, generation_number).
    pub fn get_object(&self, id: (u32, u16)) -> Option<&PdfObject> {
        self.objects.get(&id)
    }

    /// Resolve a PdfObject: if it's a Reference, follow it to the actual object.
    /// If not a reference, return the object itself.
    pub fn resolve<'a>(&'a self, obj: &'a PdfObject) -> &'a PdfObject {
        let mut current = obj;
        for _ in 0..10 {
            if let PdfObject::Reference(n, g) = current {
                if let Some(resolved) = self.objects.get(&(*n, *g)) {
                    current = resolved;
                } else {
                    return current;
                }
            } else {
                return current;
            }
        }
        current
    }

    /// Get the trailer dictionary.
    pub fn trailer(&self) -> &PdfDict {
        &self.trailer
    }

    /// Get the catalog dictionary (via trailer /Root reference).
    pub fn catalog(&self) -> Result<&PdfDict> {
        let root_ref = dict_get(&self.trailer, b"Root")
            .ok_or_else(|| Error::MissingObject("trailer /Root".into()))?;
        let root = self.resolve(root_ref);
        root.as_dict()
            .ok_or_else(|| Error::PdfParse("catalog is not a dictionary".into()))
    }

    /// Get all pages as (1-based page_number -> (obj_num, gen_num)).
    /// Traverses the page tree: Catalog -> Pages -> Kids.
    pub fn pages(&self) -> BTreeMap<u32, (u32, u16)> {
        self.scan_page_tree().pages
    }

    /// Get the number of pages.
    pub fn page_count(&self) -> u32 {
        self.pages().len() as u32
    }

    /// Page count as declared by the root `Pages` node (`/Count`), when it is readable.
    ///
    /// Independent of [`Self::pages`], which reports what the walk could actually reach.
    /// The two disagreeing means the file is damaged — see [`PageTreeScan`].
    pub fn declared_page_count(&self) -> Option<u32> {
        let root = self
            .catalog()
            .ok()
            .and_then(|c| dict_get(c, b"Pages"))
            .and_then(|r| r.as_reference())?;
        let count = dict_get(self.get_dict(root).ok()?, b"Count").and_then(|o| o.as_i64())?;
        u32::try_from(count).ok()
    }

    /// Number of objects the xref table pointed at that could not be loaded.
    pub fn skipped_object_count(&self) -> usize {
        self.skipped_objects
    }

    /// Walk the page tree, reporting both the pages reached and what had to be dropped.
    ///
    /// Depth-first over an explicit stack rather than by recursion: the page tree of a
    /// damaged (or hostile) file can nest arbitrarily deep or point back at itself, and
    /// neither may cost the caller its stack. A `visited` set makes cycles terminate.
    pub fn scan_page_tree(&self) -> PageTreeScan {
        let mut scan = PageTreeScan::default();

        // No usable catalog or root `Pages` loses every page at once. Report it as one
        // unusable node so callers see "incomplete", not "this document has no pages".
        let Some(root) = self
            .catalog()
            .ok()
            .and_then(|c| dict_get(c, b"Pages"))
            .and_then(|r| r.as_reference())
        else {
            scan.unresolved_nodes += 1;
            return scan;
        };

        let mut page_num = 1u32;
        let mut visited: HashSet<(u32, u16)> = HashSet::new();
        let mut stack = vec![root];

        while let Some(node_id) = stack.pop() {
            // Already walked: a cyclic or diamond page tree. Not a loss — just done.
            if !visited.insert(node_id) {
                continue;
            }

            let Ok(dict) = self.get_dict(node_id) else {
                scan.unresolved_nodes += 1;
                continue;
            };

            match dict_get(dict, b"Type").and_then(|o| o.as_name()) {
                Some(b"Page") => {
                    scan.pages.insert(page_num, node_id);
                    page_num += 1;
                }
                // `/Type` is optional on intermediate nodes in practice — treat absent
                // as a `Pages` node and recurse into Kids.
                Some(b"Pages") | None => {
                    if let Some(kids) = dict_get(dict, b"Kids").and_then(|o| o.as_array()) {
                        // Push in reverse so the leftmost kid pops first (document order).
                        for kid in kids.iter().rev() {
                            match kid.as_reference() {
                                Some(kid_id) => stack.push(kid_id),
                                None => scan.unresolved_nodes += 1,
                            }
                        }
                    }
                }
                // Neither a page nor a page-tree node: the subtree below it is unreachable.
                Some(_) => scan.unresolved_nodes += 1,
            }
        }

        scan
    }

    /// Get a dictionary by object ID, resolving references.
    pub fn get_dict(&self, id: (u32, u16)) -> Result<&PdfDict> {
        let obj = self
            .get_object(id)
            .ok_or_else(|| Error::MissingObject(format!("object {:?}", id)))?;
        let resolved = self.resolve(obj);
        match resolved {
            PdfObject::Dict(d) => Ok(d),
            PdfObject::Stream(s) => Ok(&s.dict),
            _ => Err(Error::PdfParse(format!(
                "object {:?} is not a dictionary",
                id
            ))),
        }
    }

    /// Check if the document is encrypted.
    pub fn is_encrypted(&self) -> bool {
        dict_get(&self.trailer, b"Encrypt").is_some()
    }
}

/// Recursively decrypt strings and streams within a PDF object.
fn decrypt_object(obj: &mut PdfObject, key: &[u8], use_aes: bool) {
    match obj {
        PdfObject::Str(data) => {
            if use_aes {
                if let Some(decrypted) = crypt::decrypt_aes128(key, data) {
                    *data = decrypted;
                }
            } else {
                *data = crypt::decrypt_rc4(key, data);
            }
        }
        PdfObject::Stream(stream) => {
            if use_aes {
                if let Some(decrypted) = crypt::decrypt_aes128(key, &stream.raw_data) {
                    stream.raw_data = decrypted;
                }
            } else {
                stream.raw_data = crypt::decrypt_rc4(key, &stream.raw_data);
            }
        }
        PdfObject::Array(arr) => {
            for item in arr.iter_mut() {
                decrypt_object(item, key, use_aes);
            }
        }
        PdfObject::Dict(dict) => {
            for val in dict.values_mut() {
                decrypt_object(val, key, use_aes);
            }
        }
        _ => {}
    }
}

/// Parse the PDF version from the file header (`%PDF-X.Y`).
fn parse_version(data: &[u8]) -> Result<String> {
    if data.len() < 8 || &data[0..5] != b"%PDF-" {
        return Err(Error::UnknownFormat);
    }
    // Extract version string until whitespace or end
    let version_start = 5;
    let mut end = version_start;
    while end < data.len() && !data[end].is_ascii_whitespace() {
        end += 1;
    }
    let version = std::str::from_utf8(&data[version_start..end])
        .map_err(|_| Error::PdfParse("invalid version string".into()))?;
    Ok(version.to_string())
}

/// Extract objects from an ObjStm (Object Stream).
///
/// The stream contains N objects. The dictionary has:
/// - `/N`: number of objects
/// - `/First`: byte offset of the first object data (after the header pairs)
///
/// The header consists of N pairs of integers: obj_number byte_offset
/// The byte_offset is relative to `/First`.
fn extract_objstm_objects(pdf_stream: &PdfStream) -> Result<HashMap<usize, PdfObject>> {
    let n = dict_get(&pdf_stream.dict, b"N")
        .and_then(|o| o.as_i64())
        .ok_or_else(|| Error::PdfParse("ObjStm missing /N".into()))? as usize;

    let first = dict_get(&pdf_stream.dict, b"First")
        .and_then(|o| o.as_i64())
        .ok_or_else(|| Error::PdfParse("ObjStm missing /First".into()))? as usize;

    let decompressed = stream::decompress(pdf_stream)?;

    // Parse header: N pairs of (obj_number, byte_offset)
    let mut pos = 0;
    let mut offsets: Vec<(u32, usize)> = Vec::with_capacity(n);

    for _ in 0..n {
        pos = skip_ws(&decompressed, pos);
        let (obj_num, new_pos) = parse_int(&decompressed, pos)?;
        pos = skip_ws(&decompressed, new_pos);
        let (byte_offset, new_pos) = parse_int(&decompressed, pos)?;
        pos = new_pos;
        offsets.push((obj_num as u32, byte_offset as usize));
    }

    // Parse each object
    let mut result = HashMap::new();
    for (index, &(_obj_num, byte_offset)) in offsets.iter().enumerate() {
        let obj_pos = first + byte_offset;
        if obj_pos < decompressed.len() {
            if let Ok((obj, _)) = tokenizer::parse_object(&decompressed, obj_pos) {
                result.insert(index, obj);
            }
        }
    }

    Ok(result)
}

fn skip_ws(data: &[u8], mut pos: usize) -> usize {
    while pos < data.len() && data[pos].is_ascii_whitespace() {
        pos += 1;
    }
    pos
}

fn parse_int(data: &[u8], pos: usize) -> Result<(i64, usize)> {
    let start = pos;
    let mut p = pos;
    if p < data.len() && (data[p] == b'+' || data[p] == b'-') {
        p += 1;
    }
    while p < data.len() && data[p].is_ascii_digit() {
        p += 1;
    }
    if p == start {
        return Err(Error::PdfParse(format!(
            "expected integer at offset {}",
            pos
        )));
    }
    let s = std::str::from_utf8(&data[start..p])
        .map_err(|_| Error::PdfParse("invalid integer".into()))?;
    let val: i64 = s
        .parse()
        .map_err(|_| Error::PdfParse("invalid integer".into()))?;
    Ok((val, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a PDF here rather than reading one from disk.
    ///
    /// These tests used to load `test-files/basic/*.pdf` through a helper that returned `None`
    /// when the file was missing, and every caller then returned early -- so with `test-files/`
    /// gitignored and never present, all six reported green without executing a single
    /// assertion. A fixture the test assembles cannot go missing, and it also says in the test
    /// exactly which bytes the behaviour depends on.
    fn pdf(objects: Vec<Vec<u8>>, root: usize) -> Vec<u8> {
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

    /// Catalog, page tree, one page, one content stream.
    fn one_page_pdf() -> Vec<u8> {
        pdf(
            vec![
                b"<</Type/Catalog/Pages 2 0 R>>".to_vec(),
                b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec(),
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Contents 4 0 R>>".to_vec(),
                b"<</Length 38>>\nstream\nBT /F1 12 Tf 72 720 Td (Hi) Tj ET\n\nendstream".to_vec(),
            ],
            1,
        )
    }

    #[test]
    fn a_minimal_document_reports_its_version_and_page_count() {
        let doc = RawDocument::load(&one_page_pdf()).expect("a well-formed PDF loads");
        assert_eq!(doc.page_count(), 1);
        assert_eq!(
            doc.version, "1.4",
            "the header version is read, not guessed"
        );
    }

    #[test]
    fn the_catalog_is_reachable_and_points_at_the_page_tree() {
        let doc = RawDocument::load(&one_page_pdf()).unwrap();
        let catalog = doc.catalog().expect("the trailer /Root resolves");
        assert!(
            dict_get(catalog, b"Pages").is_some(),
            "a catalog without /Pages would make page enumeration silently empty"
        );
    }

    #[test]
    fn pages_are_enumerated_from_one() {
        let doc = RawDocument::load(&one_page_pdf()).unwrap();
        let pages = doc.pages();
        assert_eq!(pages.len(), 1);
        assert!(
            pages.contains_key(&1),
            "page numbering is 1-indexed across this crate API"
        );
    }

    #[test]
    fn an_enumerated_page_resolves_to_a_page_dictionary() {
        let doc = RawDocument::load(&one_page_pdf()).unwrap();
        let first = doc.pages()[&1];
        let page_dict = doc.get_dict(first).expect("the id from pages() resolves");
        assert_eq!(
            dict_get(page_dict, b"Type").and_then(|o| o.as_name()),
            Some(b"Page".as_slice()),
            "pages() must not hand back the page tree node"
        );
    }

    #[test]
    fn a_two_page_tree_is_walked_in_order() {
        // One page proves almost nothing about a tree walk: a stub returning the first Kid
        // would pass every test above.
        let doc = RawDocument::load(&pdf(
            vec![
                b"<</Type/Catalog/Pages 2 0 R>>".to_vec(),
                b"<</Type/Pages/Kids[3 0 R 4 0 R]/Count 2>>".to_vec(),
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]>>".to_vec(),
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>".to_vec(),
            ],
            1,
        ))
        .unwrap();

        assert_eq!(doc.page_count(), 2);
        let pages = doc.pages();
        assert_eq!(pages.len(), 2);
        // The second Kid must be page 2, not a second entry for page 1.
        assert_ne!(pages[&1], pages[&2]);
        let second = doc.get_dict(pages[&2]).unwrap();
        assert!(
            format!("{:?}", dict_get(second, b"MediaBox")).contains("200"),
            "page 2 should be the second Kid, not the first one again"
        );
    }

    #[test]
    fn an_encryption_revision_this_build_cannot_do_is_refused_by_kind() {
        // AES-256 (AESV3) is revision 5 or 6. Refusing it is correct -- what matters to a
        // caller is that the refusal is distinguishable, since the catch-all kind would make
        // "this build does not implement that" look like any other failure.
        let bytes = pdf(
            vec![
                b"<</Type/Catalog/Pages 2 0 R>>".to_vec(),
                b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec(),
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]>>".to_vec(),
                b"<</Filter/Standard/V 5/R 6/Length 256/P -1/O<00>/U<00>>>".to_vec(),
            ],
            1,
        );
        // The trailer built above carries no /Encrypt, so point it at object 4.
        let encrypted = String::from_utf8(bytes)
            .unwrap()
            .replace("/Root 1 0 R>>", "/Root 1 0 R/Encrypt 4 0 R>>")
            .into_bytes();

        let Err(err) = RawDocument::load(&encrypted) else {
            panic!("revision 6 is not implemented, so loading must not succeed");
        };
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::UnsupportedVersion,
            "got {err:?} -- a caller cannot branch on this if it arrives as the catch-all"
        );
    }

    #[test]
    fn a_document_outline_is_read_rather_than_ignored() {
        // The test this replaces was named for outlines and asserted only that the page count
        // was above zero -- it would have passed against a build that ignored /Outlines
        // entirely.
        let doc = RawDocument::load(&pdf(
            vec![
                b"<</Type/Catalog/Pages 2 0 R/Outlines 4 0 R>>".to_vec(),
                b"<</Type/Pages/Kids[3 0 R]/Count 1>>".to_vec(),
                b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]>>".to_vec(),
                b"<</Type/Outlines/First 5 0 R/Last 5 0 R/Count 1>>".to_vec(),
                b"<</Title(Chapter One)/Parent 4 0 R/Dest[3 0 R /Fit]>>".to_vec(),
            ],
            1,
        ))
        .unwrap();

        let catalog = doc.catalog().unwrap();
        let outlines = dict_get(catalog, b"Outlines")
            .and_then(|o| o.as_reference())
            .expect("/Outlines is a reference in the catalog");
        let root = doc.get_dict(outlines).expect("/Outlines resolves");
        let first = dict_get(root, b"First")
            .and_then(|o| o.as_reference())
            .expect("an outline root has a first child");
        let item = doc
            .get_dict(first)
            .expect("the first outline item resolves");
        assert_eq!(
            dict_get(item, b"Title").and_then(|o| o.as_str_bytes()),
            Some(b"Chapter One".as_slice()),
            "the outline item title should survive parsing"
        );
    }
}

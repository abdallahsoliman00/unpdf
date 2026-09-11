//! AI post-processing over an assembled [`Document`] — VLM image understanding
//! (design doc wiring points A and B).
//!
//! Runs once, after `PdfParser::parse`'s call to `run_stream` has fully returned:
//! at that point every page is already parsed and the rayon global pool this crate
//! parses pages on is idle for this document, so dispatching blocking network calls
//! on a *separate* dedicated pool here cannot starve page parsing the way doing the
//! same dispatch from inside the per-page parallel window would (see the design
//! plan's concurrency section — that starvation risk is what the dedicated pool
//! exists to avoid, and running post-parse sides steps it entirely rather than
//! needing the two pools to interleave).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;
use unparser_shared::ai::{
    understand_image, AiConfig, ContentBlock, ImageContext, ImageScope, ImageUnderstanding,
};

use crate::model::{Block, Document, Page, Paragraph, Table, TableCell, TableRow};

/// Number of concurrent `understand_image` calls in flight. A fixed constant for
/// this landing — surfacing it as a configurable field (`AiConfig` or a CLI/API
/// override) is deferred, per the implementation plan's own note that the exact
/// surface wants deciding alongside real usage.
const MAX_CONCURRENT_CALLS: usize = 4;

/// Runs wiring points A and B over `document`, mutating pages in place and
/// recording fallbacks into `document.extraction_quality.ai_fallback_count`.
pub(crate) fn apply(document: &mut Document, cfg: &AiConfig) {
    let fallback_count = AtomicUsize::new(0);
    let image_scope = cfg.image_scope;

    // Resources are deduplicated across the whole document before this runs, so an image block
    // on page 5 can reference bytes that only page 1 still holds. Resolving against the page
    // alone would find nothing and skip the image in silence -- the caption would simply not
    // appear, with no failure anywhere to say why.
    let shared: HashMap<String, (String, Vec<u8>)> = document
        .pages
        .iter()
        .flat_map(|p| p.images.iter())
        .map(|(id, r)| (id.clone(), (r.mime_type.clone(), r.data.clone())))
        .collect();

    let mut work = || {
        // Before the per-page pass, so no page's thread gets to caption a shared image with its
        // own context first -- see `caption_repeated_images`.
        let repeated = if image_scope == ImageScope::All {
            caption_repeated_images(&document.pages, cfg, &shared, &fallback_count)
        } else {
            Captions::new()
        };
        document.pages.par_iter_mut().for_each(|page| {
            // Eligibility is decided once, before either point mutates the page: a
            // page the OCR gate (or a plain text-less scan) left with nothing but a
            // single full-page image goes through point A exclusively — including on
            // failure. Falling through to point B on an A failure would re-send the
            // same image `understand_image` just rejected.
            if is_point_a_candidate(page) {
                process_point_a(page, cfg, &fallback_count);
            } else if image_scope == ImageScope::All {
                // Point B: individual images left over on otherwise-text pages. Only
                // when the caller asked for full coverage — `LowConfidencePagesOnly`
                // stops at A.
                process_point_b(page, cfg, &shared, &repeated, &fallback_count);
            }
        });
    };

    match rayon::ThreadPoolBuilder::new()
        .num_threads(MAX_CONCURRENT_CALLS)
        .build()
    {
        Ok(pool) => pool.install(work),
        // Pool construction failing (OS thread-creation exhaustion) is exotic enough
        // that degrading to the ambient pool, rather than skipping AI entirely, is
        // the right trade — parsing has already finished, so there is nothing left
        // for a borrowed worker to starve at this point in the pipeline.
        Err(_) => work(),
    }

    document.extraction_quality.ai_fallback_count += fallback_count.load(Ordering::Relaxed);
}

/// A page qualifies for point A when nothing but its (single) image survived
/// parsing — no paragraph or table content at all.
fn is_point_a_candidate(page: &Page) -> bool {
    page.images.len() == 1
        && !page
            .elements
            .iter()
            .any(|b| matches!(b, Block::Paragraph(_) | Block::Table(_)))
}

fn process_point_a(page: &mut Page, cfg: &AiConfig, fallback_count: &AtomicUsize) {
    let Some((resource_id, resource)) = page.images.first() else {
        return;
    };
    let resource_id = resource_id.clone();
    let mime_type = resource.mime_type.clone();
    let data = resource.data.clone();

    match understand_image(cfg, &data, &mime_type, ImageContext::default()) {
        Ok(ImageUnderstanding::Structured(blocks)) => {
            page.elements = map_content_blocks(blocks);
        }
        Ok(ImageUnderstanding::Description(text)) => {
            set_alt_text(&mut page.elements, &resource_id, text);
        }
        // A future variant this crate does not yet know how to map — same
        // treatment as a call failure: leave the image as-is, count the fallback.
        Ok(_) | Err(_) => {
            fallback_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn process_point_b(
    page: &mut Page,
    cfg: &AiConfig,
    shared: &HashMap<String, (String, Vec<u8>)>,
    repeated: &Captions,
    fallback_count: &AtomicUsize,
) {
    // Reverse order: a Structured result below can change the element count at
    // `idx`, which would invalidate every later (larger) index still to process —
    // processing high-to-low keeps every not-yet-visited index valid.
    let image_indices: Vec<usize> = page
        .elements
        .iter()
        .enumerate()
        .filter(|(_, b)| matches!(b, Block::Image { alt_text: None, .. }))
        .map(|(i, _)| i)
        .collect();

    for idx in image_indices.into_iter().rev() {
        let Block::Image { resource_id, .. } = &page.elements[idx] else {
            continue;
        };
        let resource_id = resource_id.clone();
        // An image drawn more than once was captioned once, up front; a failure there was
        // counted there -- once, not once per occurrence.
        match repeated.get(&resource_id) {
            Some(Some(understanding)) => {
                apply_at(&mut page.elements, idx, understanding.clone());
                continue;
            }
            Some(None) => continue,
            None => {}
        }
        // The page's own inventory first -- it is the common case and needs no allocation --
        // then the document-wide one, which is where a deduplicated image now lives.
        let Some((mime_type, data)) = page
            .images
            .iter()
            .find(|(id, _)| *id == resource_id)
            .map(|(_, r)| (r.mime_type.clone(), r.data.clone()))
            .or_else(|| shared.get(&resource_id).cloned())
        else {
            continue;
        };
        let preceding_text = preceding_paragraph_text(&page.elements, idx);
        let following_text = following_paragraph_text(&page.elements, idx);
        let context = ImageContext {
            preceding_text: preceding_text.as_deref(),
            following_text: following_text.as_deref(),
        };

        match understand_image(cfg, &data, &mime_type, context) {
            Ok(
                understanding @ (ImageUnderstanding::Structured(_)
                | ImageUnderstanding::Description(_)),
            ) => apply_at(&mut page.elements, idx, understanding),
            Ok(_) | Err(_) => {
                fallback_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// VLM results for the images point B would otherwise caption more than once, by resource id.
/// `None` is a call that fell back: every occurrence of that image stays uncaptioned.
type Captions = HashMap<String, Option<ImageUnderstanding>>;

/// Captions each image point B would meet more than once -- a single time, with no surrounding
/// text.
///
/// Deduplication leaves one resource for an image a document draws on several pages (a
/// running-header logo is the ordinary case), but point B still met it once per page and sent
/// each page's neighbouring paragraphs along with it: the model was paid once per page for one
/// picture, and the captions differed only because the pages did. No single page's text
/// describes an image that belongs to all of them, so this call carries none, and its result is
/// applied to every occurrence.
///
/// It runs before the per-page pass rather than as a cache inside it. In a parallel loop the
/// first page to reach the image would send its own context, and which page that is depends on
/// thread scheduling.
fn caption_repeated_images(
    pages: &[Page],
    cfg: &AiConfig,
    shared: &HashMap<String, (String, Vec<u8>)>,
    fallback_count: &AtomicUsize,
) -> Captions {
    let mut occurrences: HashMap<&str, usize> = HashMap::new();
    // A point A page is captioned whole by its own call and never reaches point B.
    for page in pages.iter().filter(|page| !is_point_a_candidate(page)) {
        for block in &page.elements {
            if let Block::Image {
                resource_id,
                alt_text: None,
                ..
            } = block
            {
                *occurrences.entry(resource_id.as_str()).or_default() += 1;
            }
        }
    }

    occurrences
        .into_iter()
        .filter(|&(_, count)| count > 1)
        .collect::<Vec<_>>()
        .into_par_iter()
        .filter_map(|(id, _)| {
            // Bytes the document does not hold cannot be sent. Leaving the id out lets point B
            // treat it exactly as it treats any other image it cannot resolve.
            let (mime_type, data) = shared.get(id)?;
            let result = match understand_image(cfg, data, mime_type, ImageContext::default()) {
                Ok(
                    understanding @ (ImageUnderstanding::Structured(_)
                    | ImageUnderstanding::Description(_)),
                ) => Some(understanding),
                Ok(_) | Err(_) => {
                    fallback_count.fetch_add(1, Ordering::Relaxed);
                    None
                }
            };
            Some((id.to_owned(), result))
        })
        .collect()
}

/// Puts a VLM result in place of (`Structured`) or onto (`Description`) the image block at
/// `idx`.
fn apply_at(elements: &mut Vec<Block>, idx: usize, understanding: ImageUnderstanding) {
    match understanding {
        ImageUnderstanding::Structured(blocks) => {
            elements.splice(idx..=idx, map_content_blocks(blocks));
        }
        ImageUnderstanding::Description(text) => {
            if let Block::Image { alt_text, .. } = &mut elements[idx] {
                *alt_text = Some(text);
            }
        }
        // Callers pass only the two variants above; one this crate does not know leaves the
        // block as it was.
        _ => {}
    }
}

fn set_alt_text(elements: &mut [Block], resource_id: &str, text: String) {
    for block in elements {
        if let Block::Image {
            resource_id: rid,
            alt_text,
            ..
        } = block
        {
            if rid == resource_id {
                *alt_text = Some(text);
                return;
            }
        }
    }
}

fn preceding_paragraph_text(elements: &[Block], idx: usize) -> Option<String> {
    elements[..idx].iter().rev().find_map(|b| match b {
        Block::Paragraph(p) => Some(p.plain_text()),
        _ => None,
    })
}

fn following_paragraph_text(elements: &[Block], idx: usize) -> Option<String> {
    elements[idx + 1..].iter().find_map(|b| match b {
        Block::Paragraph(p) => Some(p.plain_text()),
        _ => None,
    })
}

/// Maps `unparser_shared::ai`'s generic content blocks onto this crate's IR —
/// the "매핑 규칙" shared by wiring points A and B.
fn map_content_blocks(blocks: Vec<ContentBlock>) -> Vec<Block> {
    blocks
        .into_iter()
        // `filter_map`, not `map`: ContentBlock is `#[non_exhaustive]` — a future
        // variant this crate does not yet know how to map is dropped rather than
        // panicking or fabricating a placeholder block.
        .filter_map(|block| match block {
            ContentBlock::Paragraph(text) => Some(Block::Paragraph(Paragraph::with_text(text))),
            ContentBlock::Table(table_block) => {
                let mut table = Table::with_header(table_block.header_rows);
                for row in table_block.rows {
                    let cells = row
                        .into_iter()
                        .map(|cell| {
                            let mut c = TableCell::text(cell.text);
                            c.rowspan = cell.rowspan;
                            c.colspan = cell.colspan;
                            c
                        })
                        .collect();
                    table.add_row(TableRow::new(cells));
                }
                Some(Block::Table(table))
            }
            _ => None,
        })
        .collect()
}

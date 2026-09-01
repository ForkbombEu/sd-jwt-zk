---
name: SD-JWT ZK
description: A bounded proof journey in the Forkbomb Vite Theme visual language.
colors:
  structural-blue: "#0f237c"
  deep-navy: "#050d30"
  signal-mint: "#2dd8a3"
  white: "#ffffff"
  cloud: "#f7f7f7"
  mist: "#eef1f5"
  muted-ink: "#3f4b70"
  structural-rule: "rgba(15, 35, 124, 0.22)"
  signal-rule-dark: "rgba(45, 216, 163, 0.6)"
typography:
  display:
    fontFamily: "Barlow Semi Condensed, Arial Narrow, sans-serif"
    fontSize: "clamp(2.75rem, 1.7rem + 4.2vw, 5.75rem)"
    fontWeight: 600
    lineHeight: 0.98
    letterSpacing: "-0.03em"
  title:
    fontFamily: "Barlow Semi Condensed, Arial Narrow, sans-serif"
    fontSize: "clamp(2rem, 1.55rem + 1.6vw, 2.5rem)"
    fontWeight: 600
    lineHeight: 1.08
  body:
    fontFamily: "Public Sans, Arial, sans-serif"
    fontSize: "clamp(1rem, 0.95rem + 0.2vw, 1.1rem)"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "Public Sans, Arial, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 600
    lineHeight: 1.2
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace"
rounded:
  square: "0"
spacing:
  "1": "0.5rem"
  "2": "0.75rem"
  "3": "1rem"
  "4": "1.5rem"
  "5": "2rem"
  "6": "3rem"
  "7": "4.5rem"
  section: "clamp(4.5rem, 8vw, 7.5rem)"
  gutter: "clamp(1.25rem, 5vw, 4.5rem)"
components:
  button-solid:
    backgroundColor: "{colors.signal-mint}"
    textColor: "{colors.deep-navy}"
    typography: "{typography.label}"
    rounded: "{rounded.square}"
    padding: "0.75rem 2rem"
    height: "2.75rem"
  button-solid-hover:
    backgroundColor: "{colors.structural-blue}"
    textColor: "{colors.white}"
    typography: "{typography.label}"
    rounded: "{rounded.square}"
    padding: "0.75rem 2rem"
  button-outline:
    backgroundColor: "transparent"
    textColor: "{colors.structural-blue}"
    typography: "{typography.label}"
    rounded: "{rounded.square}"
    padding: "0.75rem 2rem"
    height: "2.75rem"
  proof-node:
    backgroundColor: "{colors.signal-mint}"
    textColor: "{colors.deep-navy}"
    typography: "{typography.title}"
    rounded: "{rounded.square}"
    size: "2.75rem"
---

# Design System: SD-JWT ZK

## Overview

**Creative North Star: "The Bounded Proof Rail"**

The SD-JWT ZK documentation inherits the Forkbomb Vite Theme exactly: structural blue and deep navy establish a technical field, mint marks meaningful signals, and white or cloud surfaces give dense protocol material room to read. The visual system is candid and architectural rather than ornamental. Every division should clarify a boundary, owner, state, or path through the documentation.

The homepage expresses that world as a three-stage Challenge → Prove → Verify journey, but the reusable system is broader: square geometry, one-pixel rules, condensed display type, plain reading type, and lateral depth. Forkbomb-expression watermarks may provide quiet identity on large dark fields; they stay subordinate to content and disappear in forced-colors mode.

**Key Characteristics:**

- Structural blue and deep navy fields with sparse mint signals.
- Square silhouettes and one-pixel rules throughout controls and containers.
- Barlow Semi Condensed for hierarchy; Public Sans for sustained reading.
- Lateral shadows and tonal contrast instead of floating rounded cards.
- Native VitePress navigation, search, reading, and accessibility behavior.

## Colors

The palette behaves like a protocol diagram: blue establishes structure, navy establishes depth, mint identifies the active signal, and quiet neutrals support long-form reading.

### Primary

- **Structural Blue:** The principal brand field for navigation, evidence sections, headings, and structural borders.
- **Deep Navy:** The deepest protocol field, primary text color, and high-contrast ink for mint controls.

### Secondary

- **Signal Mint:** Reserved for proof progress, active navigation, section rules, link underlines, focus outlines, and other semantically meaningful cues.
- **Accessible Signal Green:** A darker mint-derived tone for link text on light reading surfaces. Signal Mint remains the link color on dark surfaces.

### Neutral

- **White:** The main reading surface and text on dark fields.
- **Cloud:** A softly differentiated reading surface for sidebars and bounded content regions.
- **Mist:** A muted VitePress surface for low-emphasis containers.
- **Muted Ink:** Secondary copy on light fields.
- **Structural Rule:** A translucent blue divider for light fields.
- **Signal Rule on Dark:** A translucent mint divider for dark structural fields.

### Named Rules

**The Mint Means Something Rule.** Use mint to identify progress, focus, active state, or a meaningful boundary; do not spread it as ambient decoration.

**The Field Contrast Rule.** Large sections alternate white, cloud, structural blue, and deep navy so information architecture remains visible before the copy is read.

## Typography

**Display Font:** Barlow Semi Condensed (with Arial Narrow and sans-serif fallbacks)

**Body Font:** Public Sans (with Arial and sans-serif fallbacks)
**Label/Mono Font:** Public Sans for interface labels; the system monospace stack for code and the restrained Forkbomb expression

**Character:** The condensed display face makes long technical claims feel decisive without requiring oversized ornament. Public Sans keeps protocol explanations neutral, direct, and readable; monospace is functional and sparse.

### Hierarchy

- **Display:** Semibold, tightly led and tracked. Use for hero statements and the largest section claims; keep lines short and balanced.
- **Title:** Semibold with compact leading. Use for document and section hierarchy.
- **Body:** Regular with open leading. Use for explanations and lists; prose is capped at roughly 72 characters per line.
- **Lead:** A modest step above body text for a single product-defining paragraph, never a second headline.
- **Label:** Semibold and compact. Use for actions, stage ownership, navigation, and concise metadata.
- **Mono:** Use for source paths, code, and the Forkbomb expression only.

### Named Rules

**The Two-Voice Rule.** Barlow Semi Condensed speaks hierarchy; Public Sans explains. Do not introduce a third expressive typeface.

**The Short Display Rule.** Display text must remain compact enough to preserve the condensed face's authority and the site's strong field geometry.

## Layout

The site uses a centered container capped at 75rem with fluid horizontal gutters. Section padding follows one generous fluid rhythm, while internal spacing uses the compact eight-step Forkbomb scale. Desktop compositions favor asymmetric two-column grids: a statement or heading anchors one side and a protocol rail, evidence list, or supporting explanation occupies the other.

At 60rem, dense three-part rows compress and actions may drop beneath their content. Below 47.99rem, major split layouts become one column and the hero loses its viewport-height requirement. Below 30rem, actions become full-width, protocol rows become single-column, and definition lists stack. The minimum supported inline viewport is 20rem.

**The Protocol Before Cards Rule.** Use ordered rails, ruled lists, and explicit field divisions when the content describes sequence or responsibility. Cards are reserved for genuinely parallel paths or bounded comparisons.

## Elevation & Depth

The system is flat by default. Depth comes from dark-to-light field changes, one-pixel separators, oversized low-contrast watermarks, and a single pronounced lateral shadow on important light containers. The lateral direction is part of the Forkbomb inheritance: it makes a panel read as structurally offset rather than softly floating. The animated proof signal alone receives a mint glow.

### Shadow Vocabulary

- **Lateral Card:** A broad shadow cast to the inline end. Use only on major comparison and path containers.
- **Proof Signal Glow:** A compact mint glow that follows the animated rail signal; never apply it to generic controls or cards.

### Named Rules

**The Lateral Depth Rule.** When depth is needed, cast it sideways from a square surface; do not substitute soft centered elevation.

**The Flat-at-Rest Rule.** Navigation, buttons, document blocks, and ordinary containers remain flat at rest.

## Shapes

Geometry is resolutely square. Buttons, code blocks, custom blocks, pager links, proof nodes, and content cards use zero radius. Structure is drawn with one-pixel borders, two-pixel section accents, and square-ended arrow strokes. Large background fields may clip oversized expression watermarks, but content surfaces do not use decorative cutouts.

**The Square Means Exact Rule.** Preserve zero-radius corners across new controls and containers; rounding would contradict the exact, bounded relation the interface communicates.

## Components

### Buttons

- **Shape:** Square with a one-pixel border and a minimum block size of 2.75rem.
- **Primary:** Mint fill with deep navy text and generous horizontal padding. Hover inverts to structural blue with white text.
- **Outline:** Transparent with the current foreground as its border. Hover changes to mint with deep navy text.
- **Focus:** A two-pixel mint outline offset by four pixels.
- **Directional mark:** Use the authored square-ended ArrowMark SVG. Do not substitute generated text glyphs or icon-font arrows.

### Cards / Containers

- **Corner Style:** Square.
- **Background:** White or cloud on light sections; structural blue for the external side of a capability boundary.
- **Shadow Strategy:** Apply the lateral card shadow only to the homepage's major boundary and path containers.
- **Border:** Use a one-pixel inline-start rule; mint distinguishes the contrasted half of a paired boundary.
- **Internal Padding:** Fluid from 2rem to 4rem.

### Navigation

The VitePress navigation bar is a structural-blue field with white labels, mint hover and active states, and a one-pixel mint rule. Sidebar group titles use the display face. Mobile navigation preserves the same field and contrast while retaining native VitePress behavior.

### Forkbomb Brand

The brand lockup is vertically stacked, uppercase Barlow Semi Condensed with the restrained Forkbomb expression beneath it in mint monospace. The expression is identity texture, not a general-purpose icon or heading.

### Protocol Rail

The signature rail is an ordered three-node sequence. Square mint number nodes sit on a one-pixel vertical track, and one small mint signal moves from Challenge through Prove to Verify. Stage metadata is mint; stage titles are white; supporting copy is quieter white. Under reduced motion, the signal rests at the final node and all directional transitions stop.

### Evidence and Stage Rows

Evidence uses a ruled definition list; protocol stages use full-width ruled rows with a numbered index, owner and explanation, and an ArrowMark link. These patterns keep claim, source, and next action aligned without disguising them as generic feature cards.

### Release Benchmarks

The homepage benchmark field reads the latest release JSON at build time and
retains the v1.0.0 release measurements as an offline fallback. A ruled
operation table compares median wall time, raw sample range, and proof-envelope
size for every shipped family. Horizontal timing rails share one scale;
segmented artifact rails expose the presentation, credential, key-binding, and
revocation components without implying that the observations are guarantees.

The original Forkbomb Lottie animation lives in the benchmark introduction on
the structural-blue field. It plays once when it enters the viewport, pauses
while hidden or offscreen, and resolves immediately to its final frame under
reduced motion. Timing rails animate once on entry while their numeric values
remain visible before and during motion.

### Closing Attribution

The closing call to action keeps product guidance first and places the Dyne.org
Longfellow-ZK attribution as a supporting column on its right. A single mint
rule separates the relationship without turning it into a promotional card.
The supplied Longfellow-ZK Europe artwork sits beneath the linked attribution,
followed by a brief place-of-making caption. At narrow widths, the complete
attribution follows the primary actions in the same DOM and reading order.

## Do's and Don'ts

### Do:

- **Do** use structural blue and deep navy as information-bearing fields, with mint reserved for signals and active boundaries.
- **Do** preserve square geometry, one-pixel rules, lateral depth, and the established two-font hierarchy.
- **Do** keep proof, application policy, and operational trust visibly separated in layout as well as copy.
- **Do** preserve visible focus, reduced-motion behavior, forced-colors fallbacks, color-mode support, and native VitePress interaction.
- **Do** use the authored ArrowMark SVG for directional actions.

### Don't:

- **Don't** turn protocol sequence, evidence, or responsibility boundaries into a grid of interchangeable feature cards.
- **Don't** use mint as a large decorative fill when it does not communicate a signal, state, or boundary.
- **Don't** introduce rounded pills, soft centered shadows, gradient-filled controls, or generated-glyph arrows.
- **Don't** let the Forkbomb expression watermark compete with headings or body copy.
- **Don't** add raster imagery without recording its source and generation or licensing provenance in `docs/public/ASSETS.md`.

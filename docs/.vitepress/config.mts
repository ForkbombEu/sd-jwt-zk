/*
 * Copyright (C) 2026 by The Forkbomb Company
 * designed, written and maintained by Denis Roio
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import { defineConfig } from 'vitepress'

const base = process.env.GITHUB_ACTIONS ? '/sd-jwt-zk/' : '/'

const directionContract = `<!--
THESIS: The bounded proof is understood as a three-stage protocol journey, not a generic feature-card landing page.
OWN-WORLD: Exact Forkbomb Vite Theme inheritance: structural blue and deep navy fields, mint signals, square geometry, Barlow Semi Condensed display type, Public Sans reading type, one-pixel rules, and lateral depth.
STORY: Readers move from Challenge to Prove to Verify, see what each stage establishes and leaves external, then choose an implementation or assurance path.
FIRST VIEWPORT: A split deep-blue field places the product statement and primary Get started action on the left; a large three-node proof rail occupies the right and animates one mint signal through the bounded path.
FORM: Protocol journey, ranked fifth in the grounded structural list; seed 067835d4.
FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
-->`

export default defineConfig({
  title: 'SD-JWT ZK',
  description: 'Bounded zero-knowledge presentation proofs for exact-key SD-JWT credentials.',
  lang: 'en-US',
  base,
  cleanUrls: true,
  lastUpdated: true,
  head: [
    ['meta', { name: 'theme-color', content: '#0f237c' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'SD-JWT ZK' }],
    ['meta', { property: 'og:description', content: 'Small, explicit presentation proofs with a bounded V1 relation.' }],
  ],
  transformHtml(html) {
    return html.replace('<body>', `<body>\n${directionContract}`)
  },
  themeConfig: {
    logo: false,
    siteTitle: 'SD-JWT ZK',
    nav: [
      { text: 'Learn', link: '/what-it-proves' },
      { text: 'Integrate', link: '/getting-started' },
      { text: 'Assurance', link: '/security-claims' },
      { text: 'V1.0.0', link: 'https://github.com/ForkbombEu/sd-jwt-zk/releases/tag/v1.0.0' },
    ],
    sidebar: [
      {
        text: 'Understand',
        items: [
          { text: 'What it proves', link: '/what-it-proves' },
          { text: 'Architecture', link: '/architecture' },
          { text: 'Protocol', link: '/protocol' },
          { text: 'Fixed two-slot relation', link: '/two-slot-relation' },
        ],
      },
      {
        text: 'Integrate',
        items: [
          { text: 'Getting started', link: '/getting-started' },
          { text: 'Wallet and verifier workflows', link: '/workflows' },
          { text: 'Local status operations', link: '/status-operations' },
          { text: 'V1 API and identities', link: '/api' },
        ],
      },
      {
        text: 'Evaluate',
        items: [
          { text: 'Security claims', link: '/security-claims' },
          { text: 'Privacy and linkability', link: '/privacy' },
          { text: 'Unsupported features', link: '/unsupported' },
          { text: 'Release assurance', link: '/release-assurance' },
          { text: 'Proof benchmarks', link: '/performance' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Specification and vectors', link: '/specification' },
          { text: 'Glossary', link: '/glossary' },
        ],
      },
    ],
    search: { provider: 'local' },
    outline: { level: [2, 3], label: 'On this page' },
    editLink: {
      pattern: 'https://github.com/ForkbombEu/sd-jwt-zk/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/ForkbombEu/sd-jwt-zk' },
    ],
  },
})

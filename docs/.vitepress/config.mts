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

import { defineConfig } from "vitepress";

export default defineConfig({
  title: "SD-JWT ZK",
  description: "Bounded exact-key bearer and holder-bound presentations",
  cleanUrls: true,
  themeConfig: {
    nav: [{ text: "Guide", link: "/getting-started" }, { text: "Specification", link: "/specification" }],
    sidebar: [
      { text: "Overview", items: [
        { text: "What it proves", link: "/what-it-proves" },
        { text: "Architecture", link: "/architecture" },
        { text: "Protocol", link: "/protocol" },
        { text: "Two-slot relation", link: "/two-slot-relation" }
      ]},
      { text: "Operate", items: [
        { text: "Getting started", link: "/getting-started" },
        { text: "Wallet and verifier", link: "/workflows" },
        { text: "Local status", link: "/status-operations" },
        { text: "Proof benchmarks", link: "/performance" }
      ]},
      { text: "Security", items: [
        { text: "Claim matrix", link: "/security-claims" },
        { text: "Privacy", link: "/privacy" },
        { text: "Unsupported", link: "/unsupported" }
      ]},
      { text: "Reference", items: [
        { text: "V1 API", link: "/api" },
        { text: "Release assurance", link: "/release-assurance" },
        { text: "Specification", link: "/specification" },
        { text: "Glossary", link: "/glossary" }
      ]}
    ]
  }
});

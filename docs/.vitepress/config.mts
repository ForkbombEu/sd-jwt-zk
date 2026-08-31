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
        { text: "Local status", link: "/status-operations" }
      ]},
      { text: "Security", items: [
        { text: "Claim matrix", link: "/security-claims" },
        { text: "Privacy", link: "/privacy" },
        { text: "Unsupported", link: "/unsupported" }
      ]},
      { text: "Reference", items: [
        { text: "V1 API", link: "/api" },
        { text: "Specification", link: "/specification" },
        { text: "Glossary", link: "/glossary" }
      ]}
    ]
  }
});

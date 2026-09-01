# Forkbomb animation provenance

`forkbomb-animation.json` is copied unchanged from
`ForkbombEu/vite-theme@c0c354102f13ceab0c652bac2a79eb9b3f7a5270`, where it is
distributed under the repository's AGPL-3.0-or-later license.

## Country flags

`CountryFlag.vue` loads ISO-code SVGs from the pinned `svg-country-flags`
package. It is registered globally for use in Markdown:

```md
Switzerland <CountryFlag code="ch" label="Switzerland" />
European Union <CountryFlag code="eu" label="European Union" />
```

Use lowercase ISO 3166-1 alpha-2 codes. The package also includes `eu` for the
European Union. Set `decorative` only when the surrounding text already names
the country or territory.

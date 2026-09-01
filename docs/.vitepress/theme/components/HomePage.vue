<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { withBase } from 'vitepress'
import { data as benchmarks } from '../benchmarks.data'
import ArrowMark from './ArrowMark.vue'
import ForkbombAnimation from './ForkbombAnimation.vue'

const benchmarkSection = ref<HTMLElement>()
const benchmarksVisible = ref(false)
let benchmarkObserver: IntersectionObserver | undefined

onMounted(() => {
  if (!benchmarkSection.value) return
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || !('IntersectionObserver' in window)) {
    benchmarksVisible.value = true
    return
  }

  benchmarkObserver = new IntersectionObserver(([entry]) => {
    if (!entry.isIntersecting) return
    benchmarksVisible.value = true
    benchmarkObserver?.disconnect()
  }, { threshold: 0.12 })
  benchmarkObserver.observe(benchmarkSection.value)
})

onBeforeUnmount(() => benchmarkObserver?.disconnect())

const formatDuration = (milliseconds: number) => (
  milliseconds >= 1000
    ? `${(milliseconds / 1000).toFixed(2)} s`
    : `${Math.round(milliseconds)} ms`
)

const formatDurationRange = (minimum: number, maximum: number) => (
  minimum === maximum
    ? formatDuration(minimum)
    : `${minimum.toLocaleString('en-US')}–${maximum.toLocaleString('en-US')} ms`
)

const formatBytes = (bytes: number) => `${(bytes / 1024).toFixed(1)} KiB`

const formatBytesRange = (minimum: number, maximum: number) => (
  minimum === maximum
    ? formatBytes(minimum)
    : `${formatBytes(minimum)}–${formatBytes(maximum)}`
)

const formatDate = (date: string) => new Intl.DateTimeFormat('en', {
  dateStyle: 'medium',
  timeZone: 'UTC',
}).format(new Date(date))

const steps = [
  {
    title: 'Challenge',
    text: 'The relying party fixes the issuer key, audience, purpose, nonce, time window, mode, claim policy, and optional revocation-list snapshot.',
    meta: 'Public policy',
  },
  {
    title: 'Prove',
    text: 'The wallet opens exactly two scalar disclosures and proves the requested bearer or holder-bound relation without putting private witness material on the command line.',
    meta: 'Private witness',
  },
  {
    title: 'Verify',
    text: 'The relying party checks the canonical envelope, applies local policy, and consumes the nonce only after every check succeeds.',
    meta: 'Closed result',
  },
]
</script>

<template>
  <main class="sdjwt-homepage">
    <section class="sdjwt-hero" aria-labelledby="home-title">
      <div class="fb-container sdjwt-hero__grid">
        <div class="sdjwt-hero__copy">
          <h1 id="home-title">Zero Knowledge privacy for selective disclosure.</h1>
          <p>
  SD-JWT ZK is a privacy-preserving cryptographic component for digital identity. It hides bounded witness data and supports rerandomized selective-disclosure proofs, while disclosed values and public policy can still link presentations.
          </p>
          <div class="sdjwt-actions">
            <a class="fb-button fb-button--solid" :href="withBase('/getting-started')">Get started <ArrowMark /></a>
            <a class="fb-button fb-button--outline" :href="withBase('/what-it-proves')">Understand the proof <ArrowMark /></a>
          </div>
          <p class="sdjwt-hero__release">
            <span>V1.0.0</span>
            Bounded relation · Typed API · Fail-closed verification
          </p>
        </div>

        <div class="sdjwt-rail" aria-label="Protocol journey: Challenge, Prove, Verify">
          <div class="sdjwt-rail__track" aria-hidden="true">
            <span class="sdjwt-rail__signal"></span>
          </div>
          <ol>
            <li v-for="(step, index) in steps" :key="step.title">
              <span class="sdjwt-rail__node" aria-hidden="true">{{ index + 1 }}</span>
              <div>
                <h2>{{ step.title }}</h2>
                <p><strong>{{ step.meta }}.</strong> {{ step.text }}</p>
              </div>
            </li>
          </ol>
        </div>
      </div>
    </section>

    <section class="sdjwt-boundary" aria-labelledby="boundary-title">
      <div class="fb-container">
        <div class="sdjwt-section-heading">
          <h2 id="boundary-title">The proof is narrow on purpose.</h2>
          <p>
            SD-JWT ZK gives applications one inspectable relation instead of an open-ended
            credential system. The relying party remains responsible for authorization.
          </p>
        </div>

        <div class="sdjwt-boundary__grid">
          <article>
            <h3>Established inside the proof</h3>
            <ul>
              <li>An exact configured P-256 issuer key signed the credential.</li>
              <li>Exactly two bounded scalar disclosures open signed <code>_sd</code> values.</li>
              <li>The configured claim relation is true.</li>
              <li>Holder mode proves the bounded KB-JWT relation and key possession.</li>
              <li>An optional revocation check proves private <code>VALID</code> membership under the selected root.</li>
            </ul>
          </article>
          <article class="sdjwt-boundary__external">
            <h3>Remains outside the proof</h3>
            <ul>
              <li>Issuer-key governance and application authorization.</li>
              <li>Wallet key custody and durable replay storage.</li>
              <li>Snapshot authenticity, rotation, rollback, and availability.</li>
              <li>Privacy policy for public disclosed values and linkable cohorts.</li>
            </ul>
          </article>
        </div>
      </div>
    </section>

    <section class="sdjwt-stage" aria-labelledby="journey-title">
      <div class="fb-container">
        <div class="sdjwt-section-heading sdjwt-section-heading--dark">
          <h2 id="journey-title">Follow the relation from request to decision.</h2>
          <p>Each stage has one owner, one bounded job, and a failure boundary that stays visible.</p>
        </div>

        <ol class="sdjwt-stage__list">
          <li v-for="(step, index) in steps" :key="step.title">
            <span class="sdjwt-stage__index" aria-hidden="true">0{{ index + 1 }}</span>
            <div>
              <h3>{{ step.title }}</h3>
              <p><strong class="sdjwt-stage__owner">{{ step.meta }}.</strong> {{ step.text }}</p>
            </div>
            <a :href="withBase(index === 0 ? '/protocol' : index === 1 ? '/two-slot-relation' : '/api')">
              {{ index === 0 ? 'Read the protocol' : index === 1 ? 'Open the relation' : 'Review the API' }}
              <ArrowMark />
            </a>
          </li>
        </ol>
      </div>
    </section>

    <section
      ref="benchmarkSection"
      class="sdjwt-benchmarks"
      :class="{ 'is-visible': benchmarksVisible }"
      aria-labelledby="benchmarks-title"
    >
      <div class="fb-container">
        <div class="sdjwt-benchmarks__intro">
          <div>
            <h2 id="benchmarks-title">Measured proof costs, attached to the release.</h2>
            <p>
              These are medians from the raw <strong>v{{ benchmarks.version }}</strong>
              release samples, not targets or guarantees. Compare every shipped
              operation and inspect what makes up each proof envelope.
            </p>
          </div>
          <ForkbombAnimation />
        </div>

        <dl class="sdjwt-benchmarks__meta">
          <div><dt>Runner</dt><dd>{{ benchmarks.cpu }}</dd></div>
          <div><dt>Samples</dt><dd>{{ benchmarks.iterations }} per operation</dd></div>
          <div><dt>Recorded</dt><dd>{{ formatDate(benchmarks.generatedAt) }}</dd></div>
          <div>
            <dt>Source</dt>
            <dd><a :href="benchmarks.benchmarkUrl">Raw JSON <ArrowMark /></a></dd>
          </div>
        </dl>

        <div class="sdjwt-benchmarks__families">
          <article v-for="family in benchmarks.families" :key="family.name" class="sdjwt-benchmark-family">
            <header>
              <div>
                <h3>{{ family.label }}</h3>
                <p>{{ family.description }}</p>
              </div>
              <strong>{{ formatBytes(family.proofBytes) }} proof envelope</strong>
            </header>

            <div class="sdjwt-benchmark-table" role="table" :aria-label="`${family.label} operation benchmarks`">
              <div class="sdjwt-benchmark-table__head" role="row">
                <span role="columnheader">Operation</span>
                <span role="columnheader">Wall time</span>
                <span role="columnheader">Envelope</span>
              </div>
              <div v-for="operation in family.operations" :key="operation.name" class="sdjwt-benchmark-row" role="row">
                <strong role="cell">{{ operation.label }}</strong>
                <div role="cell" class="sdjwt-benchmark-row__timing">
                  <span class="sdjwt-benchmark-row__mobile-label">Wall time</span>
                  <span class="sdjwt-benchmark-row__bar" aria-hidden="true">
                    <span :style="{ '--benchmark-ratio': `${Math.max(0.045, operation.durationRatio) * 100}%` }"></span>
                  </span>
                  <span>
                    <strong>{{ formatDuration(operation.durationMs) }}</strong>
                    <small>{{ formatDurationRange(operation.durationMinMs, operation.durationMaxMs) }}</small>
                  </span>
                </div>
                <span role="cell" class="sdjwt-benchmark-row__size">
                  <span class="sdjwt-benchmark-row__mobile-label">Envelope</span>
                  <strong>{{ formatBytes(operation.proofBytes) }}</strong>
                  <small>{{ formatBytesRange(operation.proofMinBytes, operation.proofMaxBytes) }}</small>
                </span>
              </div>
            </div>

            <div class="sdjwt-artifacts">
              <div class="sdjwt-artifacts__bar" :aria-label="`${family.label} proof artifact composition`">
                <span
                  v-for="artifact in family.artifacts"
                  :key="artifact.name"
                  :class="`sdjwt-artifacts__segment sdjwt-artifacts__segment--${artifact.name}`"
                  :style="{ '--artifact-ratio': `${artifact.ratio * 100}%` }"
                  :title="`${artifact.label}: ${formatBytes(artifact.bytes)}`"
                ></span>
              </div>
              <dl>
                <div v-for="artifact in family.artifacts" :key="artifact.name">
                  <dt><span :class="`sdjwt-artifacts__key sdjwt-artifacts__key--${artifact.name}`"></span>{{ artifact.label }}</dt>
                  <dd>{{ formatBytes(artifact.bytes) }}</dd>
                </div>
              </dl>
            </div>
          </article>
        </div>

        <div class="sdjwt-benchmarks__foot">
          <p>{{ benchmarks.timingPolicy }}</p>
          <a class="fb-button fb-button--solid" :href="withBase('/performance')">How to reproduce them <ArrowMark /></a>
        </div>
      </div>
    </section>

    <section class="sdjwt-paths" aria-labelledby="paths-title">
      <div class="fb-container">
        <div class="sdjwt-section-heading">
          <h2 id="paths-title">Choose the path that matches your work.</h2>
        </div>
        <div class="sdjwt-paths__grid">
          <article>
            <h3>Build against the supported boundary.</h3>
            <p><strong class="sdjwt-paths__label">Implementation path.</strong> Install the package, construct a typed request, and keep verification policy at the application boundary.</p>
            <nav aria-label="Implementation documentation">
              <a :href="withBase('/getting-started')">Getting started <ArrowMark /></a>
              <a :href="withBase('/workflows')">Wallet and relying-party workflows <ArrowMark /></a>
              <!-- Experimental: restore the revocation-list operations path when it is ready for public use. -->
              <!-- <a :href="withBase('/status-operations')">Revocation-list operations <ArrowMark /></a> -->
            </nav>
          </article>
          <article>
            <h3>Trace every claim to evidence.</h3>
            <p><strong class="sdjwt-paths__label">Review path.</strong> Review the property matrix, public linkability surfaces, unsupported identities, and release gates.</p>
            <nav aria-label="Assurance documentation">
              <a :href="withBase('/security-claims')">Security claim matrix <ArrowMark /></a>
              <a :href="withBase('/privacy')">Privacy and linkability <ArrowMark /></a>
              <a :href="withBase('/release-assurance')">Release assurance <ArrowMark /></a>
            </nav>
          </article>
        </div>
      </div>
    </section>

    <section class="sdjwt-evidence" aria-labelledby="evidence-title">
      <div class="fb-container sdjwt-evidence__grid">
        <div>
          <h2 id="evidence-title">Evidence ships with the source.</h2>
          <p>
            The normative protocol, bounded vectors, binding matrices, parser
            mutations, sanitizer lane, and reproducible benchmark reports are live, generated directly in continuous integration builds. Semantic versioning is used to signal changes through future releases.
          </p>
          <a class="fb-button fb-button--solid" :href="withBase('/release-assurance')">Review release assurance <ArrowMark /></a>
        </div>
        <dl>
          <div><dt>Protocol</dt><dd><code>spec/sd-jwt-zk-v1.md</code></dd></div>
          <div><dt>Vectors</dt><dd><code>fixtures/compact-vectors.json</code></dd></div>
          <div><dt>Binding audit</dt><dd><code>spec/reduced-binding-matrix.json</code></dd></div>
          <div><dt>Benchmarks</dt><dd>Raw CSV, JSON, and Markdown per release</dd></div>
        </dl>
      </div>
    </section>

    <section class="sdjwt-close" aria-labelledby="close-title">
      <div class="fb-container sdjwt-close__grid">
        <div>
          <h2 id="close-title">Start with the boundary. Then build.</h2>
          <p>Read what SD-JWT ZK proves and what it deliberately leaves out before integrating the library.</p>
          <div class="sdjwt-actions">
            <a class="fb-button fb-button--solid" :href="withBase('/what-it-proves')">What it proves <ArrowMark /></a>
            <a class="fb-button fb-button--outline" :href="withBase('/unsupported')">Unsupported features <ArrowMark /></a>
          </div>
        </div>

        <div class="sdjwt-powered-column">
          <a class="sdjwt-powered" href="https://dyne.org/longfellow-zk/">
            <img
              :src="withBase('/dyne-white-logotype.svg')"
              alt=""
              width="347"
              height="258"
              loading="lazy"
              decoding="async"
            >
            <span>
              <strong>Powered by the European Longfellow-ZK community version maintained by the Dyne.org foundation</strong>
              <span>Explore Longfellow-ZK <ArrowMark /></span>
            </span>
          </a>

          <figure class="sdjwt-eurobuild">
            <a class="sdjwt-eurobuild__image-link" href="https://dyne.org/longfellow-zk/">
              <img
                :src="withBase('/eurobuild-card.jpg')"
                alt="Longfellow-ZK — Zero Knowledge for EUDI"
                width="1280"
                height="640"
                loading="lazy"
                decoding="async"
              >
            </a>
            <figcaption>
              Made with &hearts; in Europe <CountryFlag code="eu" label="European Union" />
              <br>with support by <a href="https://pacesetters.eu">PACESETTERS</a> (EU Horizon grant 101132610)
              <br>and the <a href="https://plan-b.foundation">Plan-₿ Foundation</a> in Lugano <CountryFlag code="ch" label="Switzerland" />
            </figcaption>
          </figure>
        </div>
      </div>
    </section>
  </main>
</template>

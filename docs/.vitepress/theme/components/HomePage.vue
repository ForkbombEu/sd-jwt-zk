<script setup lang="ts">
import { withBase } from 'vitepress'
import ArrowMark from './ArrowMark.vue'

const steps = [
  {
    title: 'Challenge',
    text: 'The verifier fixes the issuer key, audience, purpose, nonce, time window, mode, claim policy, and optional local status snapshot.',
    meta: 'Public policy',
  },
  {
    title: 'Prove',
    text: 'The wallet opens exactly two scalar disclosures and proves the requested bearer or holder-bound relation without putting private witness material on the command line.',
    meta: 'Private witness',
  },
  {
    title: 'Verify',
    text: 'The verifier checks the canonical envelope, applies local policy, and consumes the nonce only after every check succeeds.',
    meta: 'Closed result',
  },
]
</script>

<template>
  <main class="sdjwt-homepage">
    <section class="sdjwt-hero" aria-labelledby="home-title">
      <div class="fb-container sdjwt-hero__grid">
        <div class="sdjwt-hero__copy">
          <h1 id="home-title">Small, explicit presentation proofs.</h1>
          <p>
            SD-JWT ZK proves a fixed two-disclosure relation for exact-key bearer
            and holder-bound credentials, with optional verifier-selected local status.
          </p>
          <div class="sdjwt-actions">
            <a class="fb-button fb-button--solid" :href="withBase('/getting-started')">Get started <ArrowMark /></a>
            <a class="fb-button fb-button--outline" :href="withBase('/what-it-proves')">Inspect the boundary <ArrowMark /></a>
          </div>
          <p class="sdjwt-hero__release">
            <span>V1.0.0</span>
            Fixed relation · Typed API · Fail-closed identities
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
            V1 gives applications one inspectable relation instead of an open-ended
            credential system. The verifier remains responsible for authorization.
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
              <li>Optional status proves private <code>VALID</code> membership under the selected root.</li>
            </ul>
          </article>
          <article class="sdjwt-boundary__external">
            <h3>Remains outside the proof</h3>
            <ul>
              <li>Issuer-key governance and application authorization.</li>
              <li>Wallet key custody and durable replay storage.</li>
              <li>Snapshot authenticity, rotation, rollback, and availability.</li>
              <li>Privacy policy for public disclosed values and linkable cohorts.</li>
              <li>Independent cryptographic audit—the project has not received one.</li>
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
              <a :href="withBase('/workflows')">Wallet and verifier workflows <ArrowMark /></a>
              <a :href="withBase('/status-operations')">Local status operations <ArrowMark /></a>
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
            mutations, sanitizer lane, and reproducible benchmark reports are part
            of the repository—not claims detached from it.
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
      <div class="fb-container">
        <h2 id="close-title">Start with the boundary. Then build.</h2>
        <p>Read what V1 proves and what it deliberately leaves out before integrating the library.</p>
        <div class="sdjwt-actions">
          <a class="fb-button fb-button--solid" :href="withBase('/what-it-proves')">What it proves <ArrowMark /></a>
          <a class="fb-button fb-button--outline" :href="withBase('/unsupported')">Unsupported features <ArrowMark /></a>
        </div>
      </div>
    </section>
  </main>
</template>

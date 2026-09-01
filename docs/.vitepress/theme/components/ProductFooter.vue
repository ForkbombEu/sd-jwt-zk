<script setup lang="ts">
import { withBase } from 'vitepress'

const year = new Date().getFullYear()
</script>

<template>
  <footer class="fb-footer fb-vp-footer sdjwt-footer">
    <div class="fb-container fb-footer__inner">
      <div class="fb-stack">
        <a class="fb-brand" :href="withBase('/')">
          <span class="fb-brand__name">SD-JWT ZK</span>
          <span class="fb-brand__expression" aria-hidden="true">:(){ :|:&amp; };:</span>
        </a>
        <p>Bounded presentation proofs with an explicit security and privacy boundary.</p>
      </div>

      <div>
        <h3>Documentation</h3>
        <ul>
          <li><a :href="withBase('/getting-started')">Get started</a></li>
          <li><a :href="withBase('/security-claims')">Security claims</a></li>
          <li><a :href="withBase('/specification')">Specification</a></li>
        </ul>
      </div>

      <div>
        <h3>Project</h3>
        <ul>
          <li><a href="https://github.com/ForkbombEu/sd-jwt-zk">Source on GitHub</a></li>
          <li><a href="https://github.com/ForkbombEu/sd-jwt-zk/releases/tag/v1.0.0">Release v1.0.0</a></li>
          <li><a href="mailto:info@forkbomb.eu">Professional support</a></li>
        </ul>
      </div>
    </div>

    <div class="fb-container fb-footer__legal">
      <span>© {{ year }} The Forkbomb Company</span>
      <span>Powered by Dyne.org and Plan-₿</span>
    </div>
  </footer>
</template>

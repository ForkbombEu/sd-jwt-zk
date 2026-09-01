<script setup lang="ts">
import { withBase } from 'vitepress'

withDefaults(defineProps<{
  home?: boolean
}>(), {
  home: false,
})
</script>

<template>
  <aside
    class="sdjwt-warranty"
    :class="{ 'sdjwt-warranty--home': home }"
    aria-label="License, warranty, and professional support"
  >
    <div class="sdjwt-warranty__inner" :class="{ 'fb-container': home }">
      <div class="sdjwt-warranty__label">
        <h2>Free without warranty</h2>
        <div class="sdjwt-warranty__mark" aria-hidden="true">
          <img
            :src="withBase('/gpl-v3-logo.svg')"
            alt=""
            width="744"
            height="1052"
          >
        </div>
      </div>
      <p>
        This is free and open source software provided without warranty under
        the terms of the GNU GPL v3 license. Professional support, maintenance,
        integration services, and contractual warranty options are available
        separately. Please <a href="mailto:info@forkbomb.eu">contact us</a> for
        further information.
      </p>
    </div>
  </aside>
</template>

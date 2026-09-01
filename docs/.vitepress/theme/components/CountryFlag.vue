<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  code: string
  label?: string
  decorative?: boolean
}>(), {
  label: '',
  decorative: false,
})

const flagSources = import.meta.glob(
  '../../../../node_modules/svg-country-flags/svg/*.svg',
  { eager: true, import: 'default', query: '?url' },
) as Record<string, string>

const normalizedCode = computed(() => props.code.trim().toLowerCase())
const source = computed(() => (
  flagSources[`../../../../node_modules/svg-country-flags/svg/${normalizedCode.value}.svg`]
))
const accessibleLabel = computed(() => props.label.trim() || normalizedCode.value.toUpperCase())
</script>

<template>
  <span
    v-if="source"
    class="sdjwt-country-flag"
    :role="decorative ? undefined : 'img'"
    :aria-label="decorative ? undefined : accessibleLabel"
    :aria-hidden="decorative ? 'true' : undefined"
  >
    <img :src="source" alt="" aria-hidden="true">
  </span>
  <span
    v-else
    class="sdjwt-country-flag sdjwt-country-flag--missing"
    role="img"
    :aria-label="`Unknown flag code: ${normalizedCode}`"
    :title="`Unknown flag code: ${normalizedCode}`"
  >{{ normalizedCode.toUpperCase() || '?' }}</span>
</template>

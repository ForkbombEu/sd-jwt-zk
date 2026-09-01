<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { mountForkbombAnimation } from '../hero-animation'

const animationContainer = ref<HTMLElement>()
let destroyAnimation: (() => void) | undefined

onMounted(async () => {
  destroyAnimation = await mountForkbombAnimation(animationContainer.value)
})

onBeforeUnmount(() => destroyAnimation?.())
</script>

<template>
  <div
    ref="animationContainer"
    class="sdjwt-benchmarks__lottie"
    aria-hidden="true"
  ></div>
</template>

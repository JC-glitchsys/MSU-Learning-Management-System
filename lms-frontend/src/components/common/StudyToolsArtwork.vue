<template>
  <div class="study-tools-artwork" aria-hidden="true">
    <img :src="artwork" alt="" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import calculator from '@/assets/calculator.png'
import laptop from '@/assets/laptop.png'
import notebook from '@/assets/notebook.png'
import { getSubjectArtworkType } from '@/utils/subjectArtwork.js'

const props = defineProps({
  subject: {
    type: Object,
    default: () => ({}),
  },
})

const artworks = { calculator, laptop, notebook }
const artwork = computed(() => artworks[getSubjectArtworkType(props.subject)])
</script>

<style scoped>
.study-tools-artwork {
  position: absolute;
  inset: 0 0 0 auto;
  display: flex;
  width: 48%;
  align-items: center;
  justify-content: flex-end;
  overflow: hidden;
  pointer-events: none;
}

.study-tools-artwork img {
  width: 94%;
  height: 94%;
  object-fit: contain;
  object-position: right center;
  filter: drop-shadow(0 5px 7px rgb(32 33 36 / 12%));
}
</style>

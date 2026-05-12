<template>
  <button
    :type="type"
    :disabled="disabled"
    class="rounded-lg bg-[#800000] px-5 py-2.5 text-sm font-semibold text-white hover:bg-[#5A0000] transition disabled:opacity-50 disabled:cursor-not-allowed"
    @click="$emit('click')"
  >
    <slot />
  </button>
</template>

<script setup>
defineProps({
  type: { type: String, default: 'button' },
  disabled: Boolean,
})
defineEmits(['click'])
</script>

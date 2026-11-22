<template>
  <button
    :type="type"
    :disabled="disabled"
    class="rounded-lg bg-[#800000] px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-[#5C0000] disabled:cursor-not-allowed disabled:opacity-50"
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

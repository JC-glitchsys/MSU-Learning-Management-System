<template>
  <button
    :type="type"
    :disabled="disabled"
    :class="[
      'inline-flex items-center justify-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 [&_[data-icon]]:size-4 [&_[data-icon]]:shrink-0',
      variant === 'outline'
        ? 'border-black bg-white text-black hover:bg-gray-100'
        : 'border-black bg-[#800000] text-white hover:bg-[#680000]',
    ]"
    @click="$emit('click', $event)"
  >
    <slot />
  </button>
</template>

<script setup>
defineProps({
  variant: { type: String, default: 'default', validator: value => ['default', 'outline'].includes(value) },
  type: { type: String, default: 'button' },
  disabled: Boolean,
})

defineEmits(['click'])
</script>

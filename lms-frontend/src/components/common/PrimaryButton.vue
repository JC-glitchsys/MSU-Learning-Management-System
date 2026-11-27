<template>
  <Button :type="type" :disabled="disabled" @click="$emit('click')">
    <slot />
  </Button>
</template>

<script setup>
import Button from '../ui/Button.vue'

defineProps({
  type: { type: String, default: 'button' },
  disabled: Boolean,
})
defineEmits(['click'])
</script>

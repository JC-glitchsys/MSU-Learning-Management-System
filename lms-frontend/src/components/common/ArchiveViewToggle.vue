<template>
  <div class="inline-flex items-center gap-1 rounded-lg bg-[#F3F4F6] p-1" role="tablist" aria-label="Record status">
    <button
      type="button"
      role="tab"
      :aria-selected="!modelValue"
      class="rounded-md px-3 py-2 text-sm font-medium transition"
      :class="!modelValue ? 'bg-white text-[#343A40]' : 'text-[#667085] hover:text-[#343A40]'"
      @click="$emit('update:modelValue', false)"
    >
      Active <span class="ml-1 text-xs">{{ activeCount }}</span>
    </button>
    <button
      type="button"
      role="tab"
      :aria-selected="modelValue"
      class="rounded-md px-3 py-2 text-sm font-medium transition"
      :class="modelValue ? 'bg-white text-[#343A40]' : 'text-[#667085] hover:text-[#343A40]'"
      @click="$emit('update:modelValue', true)"
    >
      Archived <span class="ml-1 text-xs">{{ archivedCount }}</span>
    </button>
  </div>
</template>

<script setup>
defineProps({
  modelValue: { type: Boolean, default: false },
  activeCount: { type: Number, default: 0 },
  archivedCount: { type: Number, default: 0 },
})

defineEmits(['update:modelValue'])
</script>

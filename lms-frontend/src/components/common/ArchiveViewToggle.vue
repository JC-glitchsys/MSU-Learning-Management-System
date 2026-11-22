<template>
  <div class="inline-flex items-center border-b border-[#DADCE0]" role="tablist" aria-label="Record status">
    <button
      type="button"
      role="tab"
      :aria-selected="!modelValue"
      class="border-b-2 px-3 py-2 text-sm font-medium transition"
      :class="!modelValue ? 'border-[#800000] text-[#800000]' : 'border-transparent text-[#5F6368] hover:text-[#202124]'"
      @click="$emit('update:modelValue', false)"
    >
      Active <span class="ml-1 text-xs">{{ activeCount }}</span>
    </button>
    <button
      type="button"
      role="tab"
      :aria-selected="modelValue"
      class="border-b-2 px-3 py-2 text-sm font-medium transition"
      :class="modelValue ? 'border-[#800000] text-[#800000]' : 'border-transparent text-[#5F6368] hover:text-[#202124]'"
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

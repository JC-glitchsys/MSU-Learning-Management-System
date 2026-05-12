<template>
  <div class="rounded-2xl border border-[#E7DCC3] bg-white shadow-sm p-5 flex items-start gap-4">
    <!-- Icon -->
    <div class="w-12 h-12 rounded-xl flex items-center justify-center text-2xl shrink-0"
      :style="{ backgroundColor: iconBg }">
      {{ icon }}
    </div>
    <!-- Info -->
    <div class="flex-1 min-w-0">
      <p class="text-xs text-[#6B7280] font-medium uppercase tracking-wide truncate">{{ title }}</p>
      <p class="text-3xl font-bold text-[#800000] mt-0.5 leading-tight">{{ value }}</p>
      <p v-if="description" class="text-xs text-[#6B7280] mt-1 truncate">{{ description }}</p>
    </div>
  </div>
</template>

<script setup>
defineProps({
  title: String,
  value: [String, Number],
  description: String,
  icon: String,
  iconBg: { type: String, default: '#FFF8E7' },
})
</script>

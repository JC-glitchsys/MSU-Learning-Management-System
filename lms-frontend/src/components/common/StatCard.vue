<template>
  <div class="lms-stat-card p-6 bg-white rounded-2xl border border-[#E7E9EE] flex items-center gap-4 transition-colors duration-200 hover:border-[#D8DCE3]">
    <div
      class="w-11 h-11 rounded-2xl flex items-center justify-center text-[#800000] shrink-0 bg-[#FDF0F0]"
    >
      <component 
        v-if="typeof icon === 'object' || typeof icon === 'function'" 
        :is="icon" 
        class="w-5 h-5 stroke-[2]" 
      />
      <span v-else class="text-xl">{{ icon }}</span>
    </div>

    <div>
      <p class="text-sm text-[#5F6368] font-normal">{{ title }}</p>
      <p class="mt-1 text-2xl font-semibold tracking-[-0.02em] text-[#202124]">{{ value }}</p>
      <p class="mt-1 text-xs text-[#8A8F98]">{{ description }}</p>
    </div>
  </div>
</template>

<script setup>
defineProps({
  title: String,
  value: [String, Number],
  description: String,
  icon: [String, Object, Function], // In-allow natin ang component tracking systems data types
  iconBg: String
})
</script>

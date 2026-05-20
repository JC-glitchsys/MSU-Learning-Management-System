<template>
  <div class="p-6 bg-white rounded-[24px] border border-msu-border shadow-sm flex items-center gap-4 transition-all duration-200 hover:-translate-y-0.5">
    <div 
      class="w-12 h-12 rounded-xl flex items-center justify-center text-msu-maroon shrink-0 border border-msu-border"
      :style="{ backgroundColor: iconBg || '#FFFFFF' }"
    >
      <component 
        v-if="typeof icon === 'object' || typeof icon === 'function'" 
        :is="icon" 
        class="w-5 h-5 stroke-[2]" 
      />
      <span v-else class="text-xl">{{ icon }}</span>
    </div>

    <div>
      <p class="text-xs text-gray-500 font-bold uppercase tracking-wider">{{ title }}</p>
      <p class="text-2xl font-black text-msu-maroon mt-0.5">{{ value }}</p>
      <p class="text-[11px] text-[#6B7280] font-medium mt-0.5">{{ description }}</p>
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
<template>
  <div class="rounded-2xl border border-[#E7DCC3] bg-white shadow-sm">
    <div v-if="title" class="px-6 py-4 border-b border-[#E7DCC3] flex items-center justify-between">
      <h2 class="text-sm font-semibold text-[#1F1F1F]">{{ title }}</h2>
      <slot name="header-action" />
    </div>
    <div class="p-6">
      <slot />
    </div>
  </div>
</template>

<script setup>
defineProps({ title: String })
</script>

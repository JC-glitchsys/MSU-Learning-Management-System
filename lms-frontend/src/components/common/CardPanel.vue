<template>
  <section
    class="overflow-hidden rounded-[28px] border border-[#E7DCC3] bg-white shadow-sm transition-all duration-200"
    :class="softGradient ? 'bg-gradient-to-br from-white via-white to-[#FFF8E1]' : 'bg-white'"
  >
    <!-- Header -->
    <div
      v-if="title || $slots['header-action']"
      class="flex items-center justify-between gap-4 border-b border-[#E7DCC3] px-5 py-4 sm:px-6"
    >
      <div class="min-w-0">
        <h2
          v-if="title"
          class="truncate text-base font-bold tracking-tight text-[#1F2937]"
        >
          {{ title }}
        </h2>

        <p
          v-if="subtitle"
          class="mt-1 truncate text-xs font-medium text-[#6B7280]"
        >
          {{ subtitle }}
        </p>
      </div>

      <div
        v-if="$slots['header-action']"
        class="shrink-0"
      >
        <slot name="header-action" />
      </div>
    </div>

    <!-- Body -->
    <div :class="noPadding ? '' : 'p-5 sm:p-6'">
      <slot />
    </div>
  </section>
</template>

<script setup>
defineProps({
  title: {
    type: String,
    default: '',
  },
  subtitle: {
    type: String,
    default: '',
  },
  noPadding: {
    type: Boolean,
    default: false,
  },
  softGradient: {
    type: Boolean,
    default: false,
  },
})
</script>
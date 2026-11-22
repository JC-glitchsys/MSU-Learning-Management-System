<template>
  <section
    class="overflow-hidden rounded-2xl border border-[#E7E9EE] bg-white transition-colors duration-200"
      :class="'bg-white'"
  >
    <!-- Header -->
    <div
      v-if="title || $slots['header-action']"
      class="flex items-center justify-between gap-4 border-b border-[#ECEEF1] px-6 py-5"
    >
      <div class="min-w-0">
        <h2
          v-if="title"
          class="truncate text-base font-semibold text-[#202124]"
        >
          {{ title }}
        </h2>

        <p
          v-if="subtitle"
          class="mt-1 truncate text-xs font-medium text-[#5F6368]"
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
    <div :class="noPadding ? '' : 'p-6'">
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

<template>
  <div class="min-h-screen bg-[#FAFAF7]">
    <div class="flex min-h-screen">
      <!-- Sidebar -->
      <Sidebar
        :open="isSidebarOpen"
        @close="isSidebarOpen = false"
      />

      <!-- Main Area -->
      <div class="min-w-0 flex-1">
        <Topbar @toggle-sidebar="isSidebarOpen = true" />

        <main class="px-4 pb-10 pt-28 sm:px-6 lg:px-8">
          <div class="mx-auto w-full max-w-7xl">
            <router-view />
          </div>
        </main>
      </div>
    </div>

    <!-- Mobile Overlay -->
    <div
      v-if="isSidebarOpen"
      class="fixed inset-0 z-40 bg-black/30 lg:hidden"
      @click="isSidebarOpen = false"
    ></div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import Sidebar from '@/components/common/Sidebar.vue'
import Topbar from '@/components/common/Topbar.vue'

const isSidebarOpen = ref(false)
</script>
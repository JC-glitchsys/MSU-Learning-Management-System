<template>
  <div class="flex h-screen bg-[#FFF8E7] font-sans text-[#1F1F1F] overflow-hidden">
    <!-- Mobile overlay -->
    <div
      v-if="sidebarOpen"
      class="fixed inset-0 z-20 bg-black/40 lg:hidden"
      @click="sidebarOpen = false"
    />

    <!-- Sidebar -->
    <Sidebar :open="sidebarOpen" @close="sidebarOpen = false" />

    <!-- Main Content -->
    <div class="flex flex-col flex-1 overflow-hidden">
      <Topbar @toggle-sidebar="sidebarOpen = !sidebarOpen" />

      <main class="flex-1 overflow-y-auto p-5 lg:p-8">
        <router-view />
      </main>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import Sidebar from '@/components/common/Sidebar.vue'
import Topbar from '@/components/common/Topbar.vue'

const sidebarOpen = ref(false)
</script>

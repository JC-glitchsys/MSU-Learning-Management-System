<template>
  <div class="flex min-h-screen bg-[#F7F8FA]">
    <Sidebar
      :open="isSidebarOpen"
      :collapsed="isSidebarCollapsed"
      @close="isSidebarOpen = false"
      @toggle="isSidebarCollapsed = !isSidebarCollapsed"
    />

    <div class="flex min-h-screen min-w-0 flex-1 flex-col">
      <Topbar @toggle-sidebar="isSidebarOpen = true" />
      <main class="lms-main min-w-0 flex-1">
        <div class="lms-container">
          <router-view />
        </div>
      </main>
    </div>

    <!-- Mobile Overlay -->
    <div
      v-if="isSidebarOpen"
      class="fixed inset-0 z-40 bg-[#202124]/20 lg:hidden"
      @click="isSidebarOpen = false"
    ></div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import Sidebar from '@/components/common/Sidebar.vue'
import Topbar from '@/components/common/Topbar.vue'

const isSidebarOpen = ref(false)
const isSidebarCollapsed = ref(false)
</script>

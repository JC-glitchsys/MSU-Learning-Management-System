<template>
  <!-- Desktop Sidebar -->
  <aside
    class="sticky top-0 hidden h-screen shrink-0 flex-col border-r border-[#E7E9EE] bg-transparent transition-[width] duration-200 lg:flex"
    :class="collapsed ? 'w-[72px]' : 'w-64'"
  >
    <SidebarContent :collapsed="collapsed" @logout="logout" @toggle-sidebar="$emit('toggle')" />
  </aside>

  <!-- Mobile Sidebar Drawer -->
  <transition name="slide">
    <aside
      v-if="open"
      class="fixed bottom-0 left-0 top-0 z-50 flex h-full w-64 flex-col border-r border-[#DADCE0] bg-[#F8F9FA] lg:hidden"
    >
      <SidebarContent
        :mobile="true"
        @logout="logout"
        @close="$emit('close')"
      />
    </aside>
  </transition>
</template>

<script setup>
import { useRouter } from 'vue-router'
import SidebarContent from './SidebarContent.vue'

defineProps({
  open: Boolean,
  collapsed: Boolean,
})

defineEmits(['close', 'toggle'])

const router = useRouter()

function logout() {
  localStorage.removeItem('user')
  router.push('/login')
}
</script>

<style scoped>
.slide-enter-active,
.slide-leave-active {
  transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}

.slide-enter-from,
.slide-leave-to {
  transform: translateX(-100%);
}
</style>

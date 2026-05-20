<template>
  <!-- Desktop Sidebar -->
  <aside
    class="hidden h-screen w-68 shrink-0 flex-col border-r border-[#E7DCC3] bg-white transition-all duration-200 lg:flex"
  >
    <SidebarContent @logout="logout" />
  </aside>

  <!-- Mobile Sidebar Drawer -->
  <transition name="slide">
    <aside
      v-if="open"
      class="fixed bottom-0 left-0 top-0 z-50 flex h-full w-68 flex-col border-r border-[#E7DCC3] bg-white shadow-xl lg:hidden"
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
})

defineEmits(['close'])

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
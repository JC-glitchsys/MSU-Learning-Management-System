<template>
  <!-- Desktop Sidebar -->
  <aside
    class="hidden lg:flex flex-col w-64 shrink-0 bg-[#800000] text-white h-screen"
  >
    <SidebarContent @logout="logout" />
  </aside>

  <!-- Mobile Sidebar Drawer -->
  <aside
    v-if="open"
    class="fixed top-0 left-0 z-30 flex flex-col w-64 h-screen bg-[#800000] text-white lg:hidden shadow-2xl"
  >
    <SidebarContent @logout="logout" @close="$emit('close')" :mobile="true" />
  </aside>
</template>

<script setup>
import { useRouter } from 'vue-router'
import SidebarContent from './SidebarContent.vue'

defineProps({ open: Boolean })
defineEmits(['close'])

const router = useRouter()

function logout() {
  localStorage.removeItem('user')
  router.push('/login')
}
</script>

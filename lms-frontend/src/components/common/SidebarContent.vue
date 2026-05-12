<template>
  <div class="flex flex-col h-full">
    <!-- Logo area -->
    <div class="px-5 py-6 border-b border-[#5A0000]">
      <div class="flex items-center gap-3">
        <!-- MSU Seal placeholder -->
        <div class="w-10 h-10 rounded-full bg-[#D4AF37] flex items-center justify-center shrink-0">
          <span class="text-[#800000] font-bold text-sm">MSU</span>
        </div>
        <div>
          <p class="font-bold text-white text-sm leading-tight">MSU LMS</p>
          <p class="text-[#F6E7B2] text-[10px] leading-tight">Mindanao State University</p>
        </div>
      </div>
    </div>

    <!-- Role Badge -->
    <div class="px-5 pt-4 pb-2">
      <span class="inline-block text-[10px] font-semibold uppercase tracking-widest text-[#D4AF37] bg-[#5A0000] px-3 py-1 rounded-full">
        {{ roleLabel }}
      </span>
    </div>

    <!-- Nav Links -->
    <nav class="flex-1 overflow-y-auto px-3 py-2 space-y-0.5">
      <router-link
        v-for="link in navLinks"
        :key="link.to"
        :to="link.to"
        class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-150"
        :class="isActive(link.to)
          ? 'bg-white/10 text-white font-semibold border-l-2 border-[#D4AF37] pl-[10px]'
          : 'text-[#F6E7B2] hover:bg-white/10 hover:text-white'"
        @click="mobile && $emit('close')"
      >
        <span class="text-base w-5 text-center">{{ link.icon }}</span>
        <span>{{ link.label }}</span>
      </router-link>
    </nav>

    <!-- Logout -->
    <div class="p-4 border-t border-[#5A0000]">
      <button
        @click="$emit('logout')"
        class="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-[#F6E7B2] hover:bg-[#5A0000] hover:text-white transition-all"
      >
        <span class="text-base w-5 text-center">🚪</span>
        <span>Logout</span>
      </button>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'

defineProps({ mobile: Boolean })
defineEmits(['logout', 'close'])

const route = useRoute()

const user = JSON.parse(localStorage.getItem('user') || '{}')
const role = user.role || 'student'

const roleLabel = computed(() => {
  if (role === 'admin') return 'Administrator'
  if (role === 'instructor') return 'Instructor'
  return 'Student'
})

const studentLinks = [
  { label: 'Dashboard', to: '/student/dashboard', icon: '🏠' },
  { label: 'My Subjects', to: '/student/subjects', icon: '📚' },
  { label: 'Modules', to: '/student/modules', icon: '📄' },
  { label: 'Activities', to: '/student/activities', icon: '📝' },
  { label: 'My Grades', to: '/student/grades', icon: '🎓' },
  { label: 'Profile', to: '/student/profile', icon: '👤' },
]

const instructorLinks = [
  { label: 'Dashboard', to: '/instructor/dashboard', icon: '🏠' },
  { label: 'My Subjects', to: '/instructor/subjects', icon: '📚' },
  { label: 'Upload Module', to: '/instructor/upload-module', icon: '📤' },
  { label: 'Create Activity', to: '/instructor/create-activity', icon: '✏️' },
  { label: 'Submissions', to: '/instructor/submissions', icon: '📥' },
  { label: 'Grade Submission', to: '/instructor/grade-submission', icon: '🎯' },
  { label: 'Profile', to: '/instructor/profile', icon: '👤' },
]

const adminLinks = [
  { label: 'Dashboard', to: '/admin/dashboard', icon: '🏠' },
  { label: 'Manage Students', to: '/admin/students', icon: '🎓' },
  { label: 'Manage Instructors', to: '/admin/instructors', icon: '👨‍🏫' },
  { label: 'Manage Courses', to: '/admin/courses', icon: '📋' },
  { label: 'Manage Subjects', to: '/admin/subjects', icon: '📚' },
  { label: 'Enroll Students', to: '/admin/enroll', icon: '📝' },
  { label: 'Reports', to: '/admin/reports', icon: '📊' },
]

const navLinks = computed(() => {
  if (role === 'admin') return adminLinks
  if (role === 'instructor') return instructorLinks
  return studentLinks
})

function isActive(path) {
  return route.path.startsWith(path)
}
</script>

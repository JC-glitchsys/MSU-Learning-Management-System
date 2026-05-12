<template>
  <header class="bg-white border-b border-[#E7DCC3] px-5 py-3 flex items-center justify-between shrink-0 shadow-sm">
    <!-- Left: Hamburger + Page Title -->
    <div class="flex items-center gap-4">
      <button
        class="lg:hidden p-2 rounded-lg hover:bg-[#FFF8E7] text-[#800000] transition"
        @click="$emit('toggle-sidebar')"
      >
        ☰
      </button>
      <div>
        <h1 class="text-base font-semibold text-[#1F1F1F] leading-tight">{{ pageTitle }}</h1>
        <p class="text-xs text-[#6B7280]">{{ currentDate }}</p>
      </div>
    </div>

    <!-- Right: User Info -->
    <div class="flex items-center gap-3">
      <div class="text-right hidden sm:block">
        <p class="text-sm font-semibold text-[#1F1F1F] leading-tight">{{ userName }}</p>
        <p class="text-xs text-[#6B7280] capitalize">{{ userRole }}</p>
      </div>
      <div class="w-9 h-9 rounded-full bg-[#800000] flex items-center justify-center text-white text-sm font-bold shrink-0">
        {{ initials }}
      </div>
    </div>
  </header>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'

defineEmits(['toggle-sidebar'])

const user = JSON.parse(localStorage.getItem('user') || '{}')
const userName = user.name || 'User'
const userRole = user.role || 'student'

const initials = computed(() =>
  userName.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2)
)

const route = useRoute()
const pageTitleMap = {
  '/student/dashboard': 'Student Dashboard',
  '/student/subjects': 'My Subjects',
  '/student/modules': 'Modules',
  '/student/activities': 'Activities',
  '/student/grades': 'My Grades',
  '/student/profile': 'Profile',
  '/instructor/dashboard': 'Instructor Dashboard',
  '/instructor/subjects': 'My Subjects',
  '/instructor/upload-module': 'Upload Module',
  '/instructor/create-activity': 'Create Activity',
  '/instructor/submissions': 'Submissions',
  '/instructor/grade-submission': 'Grade Submission',
  '/instructor/profile': 'Profile',
  '/admin/dashboard': 'Admin Dashboard',
  '/admin/students': 'Manage Students',
  '/admin/instructors': 'Manage Instructors',
  '/admin/courses': 'Manage Courses',
  '/admin/subjects': 'Manage Subjects',
  '/admin/enroll': 'Enroll Students',
  '/admin/reports': 'Reports',
}

const pageTitle = computed(() => pageTitleMap[route.path] || 'MSU LMS')

const currentDate = computed(() => {
  return new Date().toLocaleDateString('en-PH', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
  })
})
</script>

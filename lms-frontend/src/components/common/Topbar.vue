<template>
  <header
    class="fixed left-0 right-0 top-0 z-30 px-4 pt-4 sm:px-6 lg:left-[17rem]"
  >
    <div
      class="flex h-[68px] w-full items-center justify-between gap-4 rounded-full border border-[#E7DCC3] bg-white/95 px-5 shadow-[0_16px_40px_rgba(90,0,0,0.08)] backdrop-blur-xl"
    >
      <!-- Left -->
      <div class="flex min-w-0 items-center gap-3">
        <button
          class="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full text-[#800000] transition hover:bg-[#FFF8E1] lg:hidden"
          @click="$emit('toggle-sidebar')"
          aria-label="Open sidebar"
        >
          <MenuIcon class="h-5 w-5 stroke-[2.2]" />
        </button>

        <div
          class="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[#800000] to-[#5A0000] text-white ring-2 ring-[#D4AF37]/40"
        >
          <GraduationCapIcon class="h-5 w-5 stroke-[2.2]" />
        </div>

        <div class="min-w-0">
          <h1 class="truncate text-[15px] font-semibold tracking-tight text-[#1F2937] sm:text-base">
            {{ pageTitle }}
          </h1>
          <p class="mt-0.5 hidden truncate text-[11px] font-medium text-[#6B7280] sm:block">
            {{ currentDate }}
          </p>
        </div>
      </div>

      <!-- Right -->
      <div class="flex shrink-0 items-center gap-3">
        <div
          class="hidden w-56 items-center rounded-full border border-[#E7DCC3] bg-[#FAFAF7] px-3 py-2 transition focus-within:border-[#800000] focus-within:bg-white focus-within:ring-2 focus-within:ring-[#F6E7B2] xl:flex"
        >
          <SearchIcon class="mr-2 h-4 w-4 shrink-0 text-[#800000]/70" />
          <input
            type="text"
            :placeholder="searchPlaceholder"
            class="w-full bg-transparent text-xs font-medium text-[#1F2937] outline-none placeholder:text-[#9CA3AF]"
          />
        </div>

        <button
          class="hidden h-10 w-10 items-center justify-center rounded-full border border-[#E7DCC3] bg-white text-[#800000] transition hover:bg-[#FFF8E1] md:inline-flex"
          aria-label="Notifications"
        >
          <BellIcon class="h-4 w-4 stroke-[2.2]" />
        </button>

        <div
          class="flex max-w-[220px] items-center gap-2 rounded-full border border-[#E7DCC3] bg-white px-2 py-1 shadow-sm transition hover:bg-[#FFF8E1]"
        >
          <div
            class="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[#800000] to-[#5A0000] text-xs font-bold tracking-wide text-white ring-2 ring-[#D4AF37]/50"
          >
            {{ initials }}
          </div>

          <div class="hidden min-w-0 pr-1 text-left sm:block">
            <p class="truncate text-xs font-semibold leading-tight text-[#1F2937]">
              {{ userName }}
            </p>
            <p class="mt-0.5 truncate text-[10px] font-medium capitalize text-[#6B7280]">
              {{ roleLabel }}
            </p>
          </div>

          <ChevronRightIcon class="hidden h-4 w-4 shrink-0 text-[#6B7280] sm:block" />
        </div>
      </div>
    </div>
  </header>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import {
  BellIcon,
  ChevronRightIcon,
  GraduationCapIcon,
  MenuIcon,
  SearchIcon,
} from 'lucide-vue-next'

defineEmits(['toggle-sidebar'])

const route = useRoute()

function getUser() {
  try {
    return JSON.parse(localStorage.getItem('user') || '{}')
  } catch (error) {
    return {}
  }
}

const user = getUser()

const userName = computed(() => user.name || user.email || 'User Profile')

const userRole = computed(() => {
  return String(user.role || 'student').toLowerCase().trim()
})

const roleLabel = computed(() => {
  if (userRole.value === 'admin') return 'Administrator'
  if (userRole.value === 'instructor') return 'Instructor'
  return 'Student'
})

const initials = computed(() => {
  return (
    userName.value
      .split(' ')
      .filter(Boolean)
      .map((name) => name.charAt(0))
      .join('')
      .toUpperCase()
      .slice(0, 2) || 'U'
  )
})

const pageTitleMap = {
  '/student/dashboard': 'Student Dashboard',
  '/student/subjects': 'My Subjects',
  '/student/activities': 'My Activities',
  '/student/grades': 'My Grades',
  '/student/profile': 'Profile',

  '/instructor/dashboard': 'Instructor Dashboard',
  '/instructor/subjects': 'Assigned Subjects',
  '/instructor/upload-module': 'Upload Module',
  '/instructor/create-activity': 'Create Activity',
  '/instructor/submissions': 'Student Submissions',
  '/instructor/grade-submission': 'Grade Submission',

  '/admin/dashboard': 'Admin Dashboard',
  '/admin/students': 'Manage Students',
  '/admin/instructors': 'Manage Instructors',
  '/admin/programs': 'Manage Programs',
  '/admin/subjects': 'Manage Subjects',
  '/admin/enrollment': 'Student Enrollment',
}

const pageTitle = computed(() => {
  if (route.path.startsWith('/student/subjects/')) return 'Subject Details'
  return pageTitleMap[route.path] || 'MSU LMS'
})

const searchPlaceholder = computed(() => {
  if (userRole.value === 'admin') return 'Search records...'
  if (userRole.value === 'instructor') return 'Search subjects...'
  return 'Search classwork...'
})

const currentDate = computed(() => {
  return new Date().toLocaleDateString('en-PH', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })
})
</script>
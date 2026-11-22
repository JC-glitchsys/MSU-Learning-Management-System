<template>
  <header
    class="sticky top-0 z-30 w-full border-b border-[#F0F1F3] bg-white"
  >
    <div class="flex h-14 w-full items-center justify-between gap-4 px-4 sm:px-6 lg:px-8">
      <div class="flex min-w-0 items-center gap-3">
        <button
          class="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-[#667085] transition hover:bg-[#F3F4F6] hover:text-[#343A40] lg:hidden"
          @click="$emit('toggle-sidebar')"
          aria-label="Open sidebar"
        >
          <MenuIcon class="h-5 w-5 stroke-[1.8]" />
        </button>

        <h1 class="truncate text-sm font-medium leading-5 text-[#343A40]">{{ pageTitle }}</h1>
      </div>

      <div class="flex shrink-0 items-center gap-2 sm:gap-3">
        <div
          class="topbar-search hidden h-9 w-56 items-center gap-2 rounded-lg border border-transparent bg-[#F7F8FA] px-2.5 transition focus-within:border-[#E5E7EB] focus-within:bg-white xl:flex"
        >
          <SearchIcon class="h-4 w-4 shrink-0 text-[#98A2B3]" />
          <input
            ref="searchInput"
            type="text"
            autocomplete="off"
            :placeholder="searchPlaceholder"
            class="min-w-0 flex-1 bg-transparent text-sm font-normal leading-5 text-[#343A40] outline-none placeholder:text-[#98A2B3]"
          />
          <span class="shrink-0 rounded border border-[#EAECF0] bg-white px-1.5 py-0.5 text-[10px] font-normal leading-4 text-[#98A2B3]">Ctrl K</span>
        </div>

        <button
          class="relative inline-flex h-9 w-9 items-center justify-center rounded-lg text-[#667085] transition hover:bg-[#F3F4F6] hover:text-[#343A40]"
          aria-label="Notifications"
        >
          <BellIcon class="h-[18px] w-[18px] stroke-[1.8]" />
        </button>

        <router-link :to="profilePath" class="flex items-center gap-2 rounded-lg py-1 pl-1 pr-1.5 transition hover:bg-[#F7F8FA]">
          <span class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-[#800000] text-[11px] font-medium text-white">
            <img v-if="userPhotoURL" :src="userPhotoURL" alt="" class="h-full w-full rounded-full object-cover" />
            <template v-else>{{ initials }}</template>
          </span>
          <span class="hidden max-w-40 flex-col sm:flex">
            <span class="truncate text-xs font-medium leading-4 text-[#343A40]">{{ userName }}</span>
            <span class="text-[11px] leading-4 text-[#98A2B3]">{{ roleLabel }}</span>
          </span>
        </router-link>
      </div>
    </div>
  </header>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import {
  BellIcon,
  MenuIcon,
  SearchIcon,
} from 'lucide-vue-next'

defineEmits(['toggle-sidebar'])

const route = useRoute()
const searchInput = ref(null)

function getUser() {
  try {
    return JSON.parse(localStorage.getItem('user') || '{}')
  } catch (error) {
    return {}
  }
}

const user = ref(getUser())

const userName = computed(() => user.value.name || user.value.email || 'User Profile')
const userPhotoURL = computed(() => user.value.photoURL || '')

const userRole = computed(() => {
  return String(user.value.role || 'student').toLowerCase().trim()
})
const profilePath = computed(() => `/${userRole.value}/profile`)

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
  '/instructor/profile': 'Profile',

  '/admin/dashboard': 'Admin Dashboard',
  '/admin/students': 'Manage Students',
  '/admin/instructors': 'Manage Instructors',
  '/admin/programs': 'Manage Programs',
  '/admin/subjects': 'Manage Subjects',
  '/admin/enrollment': 'Student Enrollment',
  '/admin/profile': 'Profile',
}

const pageTitle = computed(() => {
  if (route.path.startsWith('/student/subjects/')) return 'Subject Details'
  return pageTitleMap[route.path] || 'MSU LMS'
})

const searchPlaceholder = computed(() => {
  if (userRole.value === 'admin') return 'Search records'
  if (userRole.value === 'instructor') return 'Search subjects'
  return 'Search classwork'
})

function handleSearchShortcut(event) {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault()
    searchInput.value?.focus()
  }
}

onMounted(() => window.addEventListener('keydown', handleSearchShortcut))
function syncProfile() { user.value = getUser() }
onMounted(() => window.addEventListener('lms:profile-updated', syncProfile))
onUnmounted(() => {
  window.removeEventListener('keydown', handleSearchShortcut)
  window.removeEventListener('lms:profile-updated', syncProfile)
})

</script>

<template>
  <div class="flex h-full flex-col bg-transparent px-3 py-4">
    <div class="flex items-center gap-2.5 px-2 pb-4" :class="collapsed ? 'flex-col' : 'justify-between'">
      <div class="flex min-w-0 items-center gap-2.5" :class="collapsed ? 'justify-center' : ''">
        <img :src="lmsLogo" alt="MSU LMS logo" class="h-9 w-9 shrink-0 object-contain" />
        <div v-if="!collapsed" class="min-w-0">
          <h1 class="truncate text-sm font-semibold text-[#202124]">MSU LMS</h1>
          <p class="truncate text-xs font-normal text-[#8A8F98]">{{ panelLabel }}</p>
        </div>
      </div>
      <button
        v-if="mobile"
        @click="$emit('close')"
        class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-[#737983] transition hover:bg-white hover:text-[#800000]"
        aria-label="Close navigation"
      >
        <XIcon class="h-4 w-4" />
      </button>
      <button
        v-else
        @click="$emit('toggle-sidebar')"
        class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-[#737983] transition hover:bg-white hover:text-[#800000]"
        :aria-label="collapsed ? 'Expand sidebar' : 'Collapse sidebar'"
        :title="collapsed ? 'Expand sidebar' : 'Collapse sidebar'"
      >
        <PanelLeftOpenIcon v-if="collapsed" class="h-[18px] w-[18px] stroke-[1.8]" />
        <PanelLeftCloseIcon v-else class="h-[18px] w-[18px] stroke-[1.8]" />
      </button>
    </div>

    <nav aria-label="Primary navigation" class="flex-1 space-y-5 overflow-y-auto px-1 py-1">
      <section v-for="group in navGroups" :key="group.label" class="space-y-1">
        <h2 v-if="!collapsed" class="px-3 pb-1 pt-1 text-xs font-medium leading-4 text-[#9AA0A9]">{{ group.label }}</h2>
        <router-link
          v-for="item in group.items"
          :key="item.to"
          :to="item.to"
          @click="mobile ? $emit('close') : null"
          class="group flex h-10 items-center gap-2.5 rounded-xl text-sm font-normal leading-5 text-[#555B65] transition-colors hover:bg-[#F7F7F8] hover:text-[#202124]"
          :class="collapsed ? 'justify-center px-0' : 'px-3'"
          active-class="bg-[#FDF0F0] !font-medium !text-[#800000]"
          :title="collapsed ? item.label : undefined"
        >
          <component :is="item.icon" class="h-[18px] w-[18px] shrink-0 stroke-[1.8] text-[#858B95] transition-colors group-hover:text-[#800000]" />
          <span v-if="!collapsed" class="truncate">{{ item.label }}</span>
        </router-link>
      </section>
    </nav>

    <div class="relative mt-3 border-t border-[#ECEEF1] pt-3">
      <div
        v-if="showSignOutConfirmation"
        class="absolute z-20 mb-2 rounded-xl border border-[#E7E9EE] bg-white p-3"
        :class="collapsed ? 'bottom-0 left-full ml-2 w-56' : 'bottom-full left-0 right-0'"
        role="dialog"
        aria-label="Confirm sign out"
      >
        <p class="text-xs font-medium leading-4 text-[#202124]">Are you sure you want to sign out?</p>
        <div class="mt-3 flex justify-end gap-2">
          <button aria-label="Cancel sign out" class="rounded-lg px-2.5 py-1.5 text-xs text-[#737983] hover:bg-[#F7F7F8]" @click="showSignOutConfirmation = false">Cancel</button>
          <button aria-label="Confirm sign out" class="rounded-lg bg-[#800000] px-2.5 py-1.5 text-xs font-medium text-white hover:bg-[#5C0000]" @click="confirmSignOut">Sign out</button>
        </div>
      </div>
      <button
        @click="showSignOutConfirmation = !showSignOutConfirmation"
        class="group flex h-10 w-full items-center gap-2.5 rounded-xl text-sm font-normal leading-5 text-[#737983] transition-colors hover:bg-[#F7F7F8] hover:text-[#800000]"
        :class="collapsed ? 'justify-center px-0' : 'px-3'"
        :title="collapsed ? 'Sign out' : undefined"
        :aria-expanded="showSignOutConfirmation"
      >
        <LogOutIcon class="h-[18px] w-[18px] stroke-[1.8]" />
        <span v-if="!collapsed">Sign out</span>
      </button>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import lmsLogo from '@/assets/logo.png'
import {
  LayoutDashboardIcon,
  UsersIcon,
  GraduationCapIcon,
  FolderIcon,
  BookOpenIcon,
  FileCheckIcon,
  LogOutIcon,
  UploadIcon,
  ClipboardListIcon,
  CheckSquareIcon,
  LibraryBigIcon,
  NotebookTabsIcon,
  UserIcon,
  ChartNoAxesColumnIcon,
  XIcon,
  PanelLeftCloseIcon,
  PanelLeftOpenIcon,
} from 'lucide-vue-next'

defineProps({
  mobile: Boolean,
  collapsed: Boolean,
})

const emit = defineEmits(['close', 'logout', 'toggle-sidebar'])
const showSignOutConfirmation = ref(false)

function confirmSignOut() {
  showSignOutConfirmation.value = false
  emit('logout')
}

function getLoggedInUser() {
  try {
    return JSON.parse(localStorage.getItem('user') || '{}')
  } catch (error) {
    return {}
  }
}

const loggedInUser = getLoggedInUser()

const role = computed(() => {
  return String(loggedInUser?.role || 'student')
    .toLowerCase()
    .trim()
})

const panelLabel = computed(() => {
  if (role.value === 'admin') return 'Admin Console'
  if (role.value === 'instructor') return 'Instructor Workspace'
  return 'Student Classroom'
})

const adminMenu = [
  {
    to: '/admin/dashboard',
    label: 'System Dashboard',
    icon: LayoutDashboardIcon,
  },
  {
    to: '/admin/students',
    label: 'Manage Students',
    icon: UsersIcon,
  },
  {
    to: '/admin/instructors',
    label: 'Manage Instructors',
    icon: GraduationCapIcon,
  },
  {
    to: '/admin/programs',
    label: 'Manage Programs',
    icon: FolderIcon,
  },
  {
    to: '/admin/subjects',
    label: 'Manage Subjects',
    icon: BookOpenIcon,
  },
  {
    to: '/admin/enrollment',
    label: 'Student Enrollment',
    icon: FileCheckIcon,
  },
  {
    to: '/admin/profile',
    label: 'Profile',
    icon: UserIcon,
  },
]

const instructorMenu = [
  {
    to: '/instructor/dashboard',
    label: 'Faculty Dashboard',
    icon: LayoutDashboardIcon,
  },
  {
    to: '/instructor/subjects',
    label: 'My Subjects',
    icon: BookOpenIcon,
  },
  {
    to: '/instructor/upload-module',
    label: 'Upload Modules',
    icon: UploadIcon,
  },
  {
    to: '/instructor/create-activity',
    label: 'Create Activities',
    icon: ClipboardListIcon,
  },
  {
    to: '/instructor/submissions',
    label: 'Submissions',
    icon: FileCheckIcon,
  },
  {
    to: '/instructor/grade-submission',
    label: 'Grade Submission',
    icon: CheckSquareIcon,
  },
  {
    to: '/instructor/profile',
    label: 'Profile',
    icon: UserIcon,
  },
]

const studentMenu = [
  {
    to: '/student/dashboard',
    label: 'Student Dashboard',
    icon: LayoutDashboardIcon,
  },
  {
    to: '/student/subjects',
    label: 'My Subjects',
    icon: LibraryBigIcon,
  },
  {
    to: '/student/activities',
    label: 'My Activities',
    icon: NotebookTabsIcon,
  },
  {
    to: '/student/grades',
    label: 'My Grades',
    icon: ChartNoAxesColumnIcon,
  },
  {
    to: '/student/profile',
    label: 'Profile',
    icon: UserIcon,
  },
]

const navGroups = computed(() => {
  const items = role.value === 'admin' ? adminMenu : role.value === 'instructor' ? instructorMenu : studentMenu
  const profileIndex = items.findIndex((item) => item.to.endsWith('/profile'))
  const coreItems = profileIndex >= 0 ? items.slice(1, profileIndex) : items.slice(1)
  const groups = [
    { label: 'Overview', items: items.slice(0, 1) },
    { label: role.value === 'admin' ? 'Administration' : role.value === 'instructor' ? 'Teaching' : 'Learning', items: coreItems },
  ]
  if (profileIndex >= 0) groups.push({ label: 'Account', items: items.slice(profileIndex) })
  return groups.filter((group) => group.items.length)
})
</script>

<style scoped>
:deep(.router-link-active svg) { color: #800000; }
</style>

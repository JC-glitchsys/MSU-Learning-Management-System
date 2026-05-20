<template>
  <div class="flex h-full flex-col bg-white">
    <!-- Brand Header -->
    <div class="flex items-center justify-between border-b border-[#E7DCC3] p-6">
      <div class="flex items-center gap-3">
        <div
          class="flex h-9 w-9 items-center justify-center rounded-full bg-[#800000] text-xs font-black text-white"
        >
          M
        </div>

        <div>
          <h1 class="text-xs font-black uppercase tracking-widest text-[#800000]">
            MSU LMS
          </h1>
          <p class="text-[10px] font-bold text-gray-400">
            {{ panelLabel }}
          </p>
        </div>
      </div>

      <button
        v-if="mobile"
        @click="$emit('close')"
        class="text-sm text-gray-400 transition hover:text-[#800000] lg:hidden"
      >
        ✕
      </button>
    </div>

    <!-- Navigation -->
    <nav class="flex-1 space-y-1 overflow-y-auto p-4">
      <router-link
        v-for="item in menuItems"
        :key="item.to"
        :to="item.to"
        @click="mobile ? $emit('close') : null"
        class="group flex items-center gap-3 rounded-xl px-4 py-3 text-xs font-bold text-[#1F2937] transition-all duration-150 hover:bg-[#FFF8E1] hover:text-[#800000]"
        active-class="bg-[#FFF8E1] !text-[#800000] border-l-4 border-[#800000] rounded-l-none"
      >
        <component
          :is="item.icon"
          class="h-4 w-4 stroke-[2] text-gray-400 transition-colors group-hover:text-[#800000]"
        />
        <span class="truncate">{{ item.label }}</span>
      </router-link>
    </nav>

    <!-- Logout -->
    <div class="border-t border-[#E7DCC3] bg-white p-4">
      <button
        @click="$emit('logout')"
        class="group flex w-full items-center gap-3 rounded-xl px-4 py-3 text-xs font-bold text-red-600 transition-colors hover:bg-red-50"
      >
        <LogOutIcon class="h-4 w-4 stroke-[2]" />
        <span>Terminate Session</span>
      </button>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
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
} from 'lucide-vue-next'

defineProps({
  mobile: Boolean,
})

defineEmits(['close', 'logout'])

const loggedInUser = computed(() => {
  try {
    return JSON.parse(localStorage.getItem('user') || '{}')
  } catch (error) {
    return {}
  }
})

const role = computed(() => {
  return String(loggedInUser.value?.role || 'student')
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

const menuItems = computed(() => {
  if (role.value === 'admin') return adminMenu
  if (role.value === 'instructor') return instructorMenu
  return studentMenu
})
</script>
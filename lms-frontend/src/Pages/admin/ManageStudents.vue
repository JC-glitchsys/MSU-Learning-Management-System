<template>
  <div class="space-y-6">
    <section class="flex flex-wrap items-end justify-between gap-4 border-b border-[#DADCE0] pb-5">
      <div>
        <h1 class="mt-1 text-2xl font-semibold tracking-tight text-[#202124]">Manage Students</h1>
        <p class="mt-1 text-sm text-[#5F6368]">View student accounts and manage active or archived records.</p>
      </div>
      <span class="rounded-md bg-[#F8F9FA] px-3 py-1.5 text-xs font-medium text-[#5F6368]">
        {{ filteredStudents.length }} student{{ filteredStudents.length === 1 ? '' : 's' }}
      </span>
    </section>

    <section class="flex flex-col gap-4 border-b border-[#DADCE0] pb-4 md:flex-row md:items-center md:justify-between">
      <label class="flex h-10 w-full items-center rounded-lg border border-[#DADCE0] bg-white px-3 transition focus-within:border-[#800000] md:max-w-lg">
        <SearchIcon class="mr-2 h-4 w-4 shrink-0 text-[#800000]/70" />
        <input v-model="searchQuery" type="search" placeholder="Search by name, email, student number, or program..." class="w-full bg-transparent text-sm text-[#202124] outline-none placeholder:text-[#5F6368]" />
      </label>
      <ArchiveViewToggle v-model="showArchived" :active-count="activeCount" :archived-count="archivedCount" />
    </section>

    <section class="overflow-hidden rounded-lg border border-[#DADCE0] bg-white">
      <SkeletonLoader v-if="loading" variant="table" class="p-6" />
      <div v-else-if="error" class="p-12 text-center">
        <AlertCircleIcon class="mx-auto h-8 w-8 text-[#B3261E]" />
        <p class="mt-3 text-sm text-[#B3261E]">{{ error }}</p>
      </div>
      <div v-else-if="filteredStudents.length === 0" class="p-12 text-center">
        <UsersIcon class="mx-auto h-8 w-8 text-[#9AA0A6]" />
        <h2 class="mt-3 text-base font-semibold text-[#202124]">No {{ showArchived ? 'archived' : 'active' }} students found</h2>
        <p class="mt-1 text-sm text-[#5F6368]">Try another search or switch the record status.</p>
      </div>
      <template v-else>
        <div class="hidden grid-cols-12 gap-4 border-b border-[#DADCE0] bg-[#F8F9FA] px-5 py-3 text-xs font-semibold uppercase tracking-wide text-[#5F6368] lg:grid">
          <div class="col-span-4">Student</div><div class="col-span-3">Program</div><div class="col-span-3">Contact</div><div class="col-span-2 text-right">Action</div>
        </div>
        <div class="divide-y divide-[#DADCE0]/70">
          <article v-for="student in filteredStudents" :key="student.id" class="grid grid-cols-1 gap-4 px-5 py-4 transition-colors hover:bg-[#F8F9FA] lg:grid-cols-12 lg:items-center">
            <div class="min-w-0 lg:col-span-4">
              <div class="flex items-center gap-3">
                <img v-if="student.photoURL" :src="student.photoURL" alt="" class="h-10 w-10 rounded-full border border-[#DADCE0] object-cover" />
                <div v-else class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#FDF0F0] text-xs font-semibold text-[#800000]">{{ initials(student.name) }}</div>
                <div class="min-w-0">
                  <p class="truncate text-sm font-semibold text-[#202124]">{{ student.name || 'Unnamed Student' }}</p>
                  <p class="mt-0.5 truncate text-xs text-[#5F6368]">Student no.: {{ student.studentNumber || 'Not provided' }}</p>
                </div>
              </div>
            </div>
            <div class="min-w-0 lg:col-span-3">
              <p class="text-[10px] font-semibold uppercase tracking-wide text-[#5F6368] lg:hidden">Program</p>
              <p class="mt-1 truncate text-sm font-medium text-[#202124] lg:mt-0">{{ student.program || 'Not assigned' }}</p>
              <p class="mt-0.5 text-xs text-[#5F6368]">{{ student.yearLevel || 'Year level not provided' }}</p>
            </div>
            <div class="min-w-0 lg:col-span-3">
              <p class="text-[10px] font-semibold uppercase tracking-wide text-[#5F6368] lg:hidden">Contact</p>
              <p class="mt-1 truncate text-sm text-[#202124] lg:mt-0">{{ student.email || 'No email' }}</p>
              <p class="mt-0.5 truncate text-xs text-[#5F6368]">{{ student.contact || 'No contact number' }}</p>
            </div>
            <div class="flex lg:col-span-2 lg:justify-end">
              <button type="button" @click="toggleArchive(student)" class="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-[#E7C5C5] bg-white px-3 text-xs font-medium text-[#9F2424] transition hover:bg-[#FDF0F0]">
                <component :is="student.archived ? ArchiveRestoreIcon : ArchiveIcon" class="h-3.5 w-3.5" />
                {{ student.archived ? 'Restore' : 'Archive' }}
              </button>
            </div>
          </article>
        </div>
      </template>
    </section>
  </div>
</template>

<script setup>
import SkeletonLoader from '@/components/common/SkeletonLoader.vue'
import { computed, onMounted, ref } from 'vue'
import { collection, getDocs, query, where } from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import { confirmAction, showResult } from '@/utils/resultMessage'
import { filterArchived, setRecordArchived } from '@/utils/archive'
import ArchiveViewToggle from '@/components/common/ArchiveViewToggle.vue'
import { AlertCircleIcon, ArchiveIcon, ArchiveRestoreIcon, SearchIcon, UsersIcon } from 'lucide-vue-next'

const students = ref([])
const loading = ref(true)
const error = ref('')
const searchQuery = ref('')
const showArchived = ref(false)

const activeCount = computed(() => students.value.filter((item) => item.archived !== true).length)
const archivedCount = computed(() => students.value.filter((item) => item.archived === true).length)
const filteredStudents = computed(() => {
  const term = searchQuery.value.trim().toLowerCase()
  return filterArchived(students.value, showArchived.value).filter((student) =>
    !term || [student.name, student.email, student.studentNumber, student.program, student.yearLevel]
      .some((value) => String(value || '').toLowerCase().includes(term)),
  )
})

async function fetchStudents() {
  loading.value = true
  error.value = ''
  try {
    const snapshot = await getDocs(query(collection(db, 'users'), where('role', '==', 'student')))
    students.value = snapshot.docs.map((item) => ({ id: item.id, ...item.data() }))
  } catch (err) {
    console.error('Fetch students error:', err)
    error.value = 'Failed to load students. Please check Firestore permissions.'
  } finally {
    loading.value = false
  }
}

async function toggleArchive(student) {
  const restoring = student.archived === true
  const accepted = await confirmAction(
    restoring ? 'Restore Student?' : 'Archive Student?',
    restoring ? 'This student account will return to the active list.' : 'This student account will be archived and can be restored later.',
    restoring ? 'Restore' : 'Archive',
  )
  if (!accepted) return
  try {
    await setRecordArchived(db, 'users', student.id, !restoring)
    await fetchStudents()
    showResult(restoring ? 'Student Restored' : 'Student Archived', restoring ? 'The student account is active again.' : 'The student account was moved to the archive.')
  } catch (err) {
    console.error('Archive student error:', err)
    showResult('Could Not Update Student', 'Please try again.', 'error')
  }
}

function initials(name) {
  return String(name || 'ST').split(' ').filter(Boolean).map((word) => word[0]).join('').toUpperCase().slice(0, 2)
}

onMounted(fetchStudents)
</script>

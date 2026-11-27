<template>
  <div class="space-y-6 animate-fade-in">
    <!-- Header -->
    <section
      class="rounded-[28px] border border-[#DADCE0] bg-gradient-to-br from-white via-white to-[#FDF0F0] p-6 shadow-sm"
    >
      <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 class="mt-1 text-2xl font-semibold tracking-tight text-[#202124]">
            Student Enrollment
          </h1>

          <p class="mt-1 max-w-2xl text-sm font-medium text-[#5F6368]">
            Enroll students into subjects and manage active subject enrollment records.
          </p>
        </div>

        <div
          class="inline-flex w-fit rounded-md bg-[#F8F9FA] px-2.5 py-1.5 text-xs font-medium text-[#5F6368]"
        >
          {{ filteredEnrollments.length }} enrollment{{ filteredEnrollments.length === 1 ? '' : 's' }}
        </div>
      </div>
    </section>

    <section class="grid grid-cols-1 gap-6 xl:grid-cols-12">
      <!-- Enrollment Form -->
      <aside class="xl:col-span-4">
        <div
          class="rounded-lg border border-[#DADCE0] bg-white p-5"
        >
          <div class="mb-5 flex items-center gap-3">
            <div
              class="flex h-11 w-11 items-center justify-center rounded-2xl bg-[#FDF0F0] text-[#800000] ring-1 ring-[#DADCE0]"
            >
              <UserPlusIcon class="h-5 w-5" />
            </div>

            <div>
              <h2 class="text-base font-black text-[#202124]">
                Enroll Student
              </h2>
              <p class="text-xs text-[#5F6368]">
                Select a student and assign a subject.
              </p>
            </div>
          </div>

          <div class="space-y-4">
            <div class="space-y-1.5">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#202124]">
                Student
              </label>

              <select
                v-model="selectedStudentId"
                class="w-full cursor-pointer rounded-[12px] border border-[#DADCE0] bg-white px-4 py-3 text-sm text-[#202124] outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
              >
                <option value="">Choose student...</option>
                <option
                  v-for="student in students"
                  :key="student.id"
                  :value="student.id"
                >
                  {{ student.name || student.email }} {{ student.studentNumber ? `(${student.studentNumber})` : '' }}
                </option>
              </select>

              <p v-if="students.length === 0" class="text-xs font-medium text-[#D93025]">
                No student records found.
              </p>
            </div>

            <div class="space-y-1.5">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#202124]">
                Subject
              </label>

              <select
                v-model="selectedSubjectId"
                class="w-full cursor-pointer rounded-[12px] border border-[#DADCE0] bg-white px-4 py-3 text-sm text-[#202124] outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#FDF0F0]"
              >
                <option value="">Choose subject...</option>
                <option
                  v-for="subject in subjects"
                  :key="subject.id"
                  :value="subject.id"
                >
                  {{ subject.code || 'No Code' }} — {{ subject.title || 'Untitled Subject' }} {{ subject.section ? `(${subject.section})` : '' }}
                </option>
              </select>

              <p v-if="subjects.length === 0" class="text-xs font-medium text-[#D93025]">
                No subjects found. Add subjects first.
              </p>
            </div>

            <button
              @click="processEnrollment"
              :disabled="enrolling"
              class="inline-flex w-full items-center justify-center gap-2 rounded-full bg-[#800000] px-5 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-[#5C0000] disabled:cursor-not-allowed disabled:opacity-60"
            >
              <LinkIcon class="h-4 w-4" />
              {{ enrolling ? 'Enrolling...' : 'Enroll Student' }}
            </button>
          </div>
        </div>
      </aside>

      <!-- Enrollment List -->
      <main class="space-y-4 xl:col-span-8">
        <!-- Search -->
        <section class="space-y-3">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="flex items-center gap-1 border-b border-[#DADCE0]">
              <ArchiveViewToggle v-model="showArchived" :active-count="activeEnrollmentsCount" :archived-count="archivedEnrollmentsCount" />
            </div>
            <button @click="fetchData" class="inline-flex h-9 items-center gap-2 rounded-md border border-[#DADCE0] bg-white px-3 text-sm font-medium text-[#5F6368] transition hover:bg-[#F8F9FA]"><RefreshCcwIcon class="h-4 w-4" /> Refresh</button>
          </div>
          <div class="flex min-h-12 items-center justify-between gap-4 rounded-lg border border-[#DADCE0] bg-white px-3 py-2">
          <div
            class="flex w-full items-center rounded-md border border-transparent bg-transparent px-2 py-1 transition focus-within:border-[#DADCE0] md:max-w-md"
          >
            <SearchIcon class="mr-2 h-4 w-4 shrink-0 text-[#800000]/70" />
            <input
              v-model="searchQuery"
              type="text"
              placeholder="Search by student, subject code, or subject title..."
              class="w-full bg-transparent text-sm font-medium text-[#202124] outline-none placeholder:text-[#5F6368]"
            />
          </div>

          </div>
        </section>

        <!-- Main Card -->
        <section class="overflow-hidden rounded-[28px] border border-[#DADCE0] bg-white shadow-sm">
          <SkeletonLoader v-if="loading" variant="table" class="p-6" />

          <div v-else-if="error" class="p-12 text-center">
            <AlertCircleIcon class="mx-auto h-10 w-10 text-[#D93025]" />
            <p class="mt-3 text-sm font-bold text-[#D93025]">
              {{ error }}
            </p>
          </div>

          <div v-else-if="filteredEnrollments.length === 0" class="p-12 text-center">
            <div
              class="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-[#FDF0F0] text-[#800000]"
            >
              <UsersIcon class="h-7 w-7" />
            </div>

            <h2 class="mt-4 text-lg font-black text-[#202124]">
              No enrollment records found
            </h2>

            <p class="mt-1 text-sm text-[#5F6368]">
              {{ showArchived ? 'Archived enrollment records will appear here.' : 'Enroll a student into a subject to create a record.' }}
            </p>
          </div>

          <div v-else class="divide-y divide-[#DADCE0]/70">
            <!-- Desktop Header -->
            <div
              class="hidden grid-cols-12 gap-4 bg-[#F8F9FA] px-6 py-4 text-xs font-black uppercase tracking-wider text-[#5F6368] lg:grid"
            >
              <div class="col-span-4">Student</div>
              <div class="col-span-5">Subject</div>
              <div class="col-span-3 text-right">Action</div>
            </div>

            <div
              v-for="enrollment in filteredEnrollments"
              :key="enrollment.id"
              class="grid grid-cols-1 gap-4 px-6 py-5 transition hover:bg-[#F8F9FA] lg:grid-cols-12 lg:items-center"
            >
              <!-- Student -->
              <div class="min-w-0 lg:col-span-4">
                <div class="flex items-center gap-3">
                  <div
                    class="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[#800000] to-[#5C0000] text-xs font-black text-white ring-2 ring-[#FDF0F0]/40"
                  >
                    {{ getInitials(enrollment.studentName) }}
                  </div>

                  <div class="min-w-0">
                    <p class="truncate text-sm font-black text-[#202124]">
                      {{ enrollment.studentName || 'Student' }}
                    </p>
                    <p class="mt-0.5 truncate text-xs font-medium text-[#5F6368]">
                      {{ enrollment.studentEmail || 'No email' }}
                    </p>
                  </div>
                </div>
              </div>

              <!-- Subject -->
              <div class="min-w-0 lg:col-span-5">
                <span
                  class="mb-1 inline-flex rounded-full border border-[#DADCE0] bg-[#FDF0F0] px-3 py-1 text-[10px] font-black uppercase tracking-wider text-[#800000]"
                >
                  {{ enrollment.subjectCode || 'Subject' }}
                </span>

                <p class="truncate text-sm font-black text-[#202124]">
                  {{ enrollment.subjectTitle || 'Untitled Subject' }}
                </p>

                <p class="mt-0.5 truncate text-xs text-[#5F6368]">
                  Instructor: {{ enrollment.instructorName || 'Unassigned' }}
                </p>
              </div>

              <!-- Action -->
              <div class="lg:col-span-3 lg:text-right">
                <button
                  @click="revokeEnrollment(enrollment.id)"
                  class="inline-flex w-full items-center justify-center gap-2 rounded-md border border-[#DADCE0] bg-white px-3 py-2 text-xs font-medium text-[#5F6368] transition hover:bg-[#F8F9FA] hover:text-[#202124] lg:w-auto"
                >
                  <component :is="enrollment.archived ? ArchiveRestoreIcon : ArchiveIcon" class="h-3.5 w-3.5" />
                  {{ enrollment.archived ? 'Restore' : 'Archive' }}
                </button>
              </div>
            </div>
          </div>
        </section>
      </main>
    </section>
  </div>
</template>

<script setup>
import SkeletonLoader from '@/components/common/SkeletonLoader.vue'
import { computed, onMounted, ref } from 'vue'
import {
  addDoc,
  collection,
  getDocs,
  query,
  serverTimestamp,
  where,
} from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import { confirmAction, showResult } from '@/utils/resultMessage'
import { filterArchived, setRecordArchived } from '@/utils/archive'
import ArchiveViewToggle from '@/components/common/ArchiveViewToggle.vue'
import {
  AlertCircleIcon,
  LinkIcon,
  RefreshCcwIcon,
  SearchIcon,
  ArchiveIcon,
  ArchiveRestoreIcon,
  UserPlusIcon,
  UsersIcon,
} from 'lucide-vue-next'

const students = ref([])
const subjects = ref([])
const enrollments = ref([])

const loading = ref(true)
const enrolling = ref(false)
const error = ref('')
const searchQuery = ref('')
const showArchived = ref(false)

const selectedStudentId = ref('')
const selectedSubjectId = ref('')

const activeEnrollmentsCount = computed(() => enrollments.value.filter((item) => item.archived !== true).length)
const archivedEnrollmentsCount = computed(() => enrollments.value.filter((item) => item.archived === true).length)

const filteredEnrollments = computed(() => {
  const keyword = searchQuery.value.toLowerCase().trim()

  const visibleEnrollments = filterArchived(enrollments.value, showArchived.value)
  if (!keyword) return visibleEnrollments

  return visibleEnrollments.filter((enrollment) => {
    return (
      enrollment.studentName?.toLowerCase().includes(keyword) ||
      enrollment.studentEmail?.toLowerCase().includes(keyword) ||
      enrollment.subjectCode?.toLowerCase().includes(keyword) ||
      enrollment.subjectTitle?.toLowerCase().includes(keyword) ||
      enrollment.instructorName?.toLowerCase().includes(keyword)
    )
  })
})

async function fetchData() {
  loading.value = true
  error.value = ''

  try {
    const studentSnapshot = await getDocs(
      query(collection(db, 'users'), where('role', '==', 'student'))
    )

    students.value = studentSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    })).filter((student) => student.archived !== true)

    const subjectSnapshot = await getDocs(collection(db, 'subjects'))

    subjects.value = subjectSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    })).filter((subject) => subject.archived !== true)

    const enrollmentSnapshot = await getDocs(collection(db, 'enrollments'))

    enrollments.value = enrollmentSnapshot.docs
      .map((document) => ({
        id: document.id,
        ...document.data(),
      }))
      .sort((a, b) => {
        const aTime = a.createdAt?.seconds || 0
        const bTime = b.createdAt?.seconds || 0
        return bTime - aTime
      })
  } catch (err) {
    console.error('Fetch enrollment data error:', err)
    error.value = 'Unable to load enrollment data. Please check Firestore permissions.'
  } finally {
    loading.value = false
  }
}

async function processEnrollment() {
  if (!selectedStudentId.value || !selectedSubjectId.value) {
    showResult('Selection Required', 'Choose both a student and a subject.', 'info')
    return
  }

  const alreadyEnrolled = enrollments.value.some((enrollment) => {
    return (
      enrollment.studentId === selectedStudentId.value &&
      enrollment.archived !== true &&
      enrollment.subjectId === selectedSubjectId.value
    )
  })

  if (alreadyEnrolled) {
    showResult('Already Enrolled', 'This student is already in the selected subject.', 'info')
    return
  }

  const selectedStudent = students.value.find(
    (student) => student.id === selectedStudentId.value
  )

  const selectedSubject = subjects.value.find(
    (subject) => subject.id === selectedSubjectId.value
  )

  if (!selectedStudent || !selectedSubject) {
    showResult('Selection Not Found', 'Choose a valid student and subject, then try again.', 'error')
    return
  }

  enrolling.value = true

  try {
    const payload = {
      studentId: selectedStudent.id,
      studentName: selectedStudent.name || selectedStudent.email || 'Unnamed Student',
      studentEmail: selectedStudent.email || '',
      subjectId: selectedSubject.id,
      subjectCode: selectedSubject.code || '',
      subjectTitle: selectedSubject.title || '',
      instructorId: selectedSubject.instructorId || '',
      instructorName: selectedSubject.instructorName || 'Unassigned',
      createdAt: serverTimestamp(),
    }

    await addDoc(collection(db, 'enrollments'), payload)

    selectedStudentId.value = ''
    selectedSubjectId.value = ''

    await fetchData()
    showResult('Student Enrolled', `${selectedStudent.name || 'The student'} was enrolled in ${selectedSubject.code || selectedSubject.title}.`)
  } catch (err) {
    console.error('Process enrollment error:', err)
    showResult('Could Not Enroll Student', 'Please try again.', 'error')
  } finally {
    enrolling.value = false
  }
}

async function revokeEnrollment(id) {
  const item = enrollments.value.find((enrollment) => enrollment.id === id)
  const restoring = item?.archived === true
  if (!await confirmAction(restoring ? 'Restore Enrollment?' : 'Archive Enrollment?', restoring ? 'This enrollment will return to the active list.' : 'This enrollment will move to the archive and can be restored later.', restoring ? 'Restore' : 'Archive')) return

  try {
    await setRecordArchived(db, 'enrollments', id, !restoring)
    await fetchData()
    showResult(restoring ? 'Enrollment Restored' : 'Enrollment Archived', restoring ? 'The enrollment is active again.' : 'The enrollment was moved to the archive.')
  } catch (err) {
    console.error('Revoke enrollment error:', err)
    showResult('Could Not Update Enrollment', 'Please try again.', 'error')
  }
}

function getInitials(name) {
  if (!name) return 'ST'

  return name
    .split(' ')
    .filter(Boolean)
    .map((word) => word.charAt(0))
    .join('')
    .toUpperCase()
    .slice(0, 2)
}

onMounted(fetchData)
</script>

<style scoped>
.animate-fade-in {
  animation: fadeIn 0.22s ease-out forwards;
}

@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(4px);
  }

  to {
    opacity: 1;
    transform: translateY(0);
  }
}
</style>

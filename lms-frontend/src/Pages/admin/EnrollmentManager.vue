<template>
  <div class="space-y-6 animate-fade-in">
    <!-- Header -->
    <section
      class="rounded-[28px] border border-[#E7DCC3] bg-gradient-to-br from-white via-white to-[#FFF8E1] p-6 shadow-sm"
    >
      <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p class="text-xs font-bold uppercase tracking-[0.22em] text-[#D4AF37]">
            Admin Enrollment
          </p>

          <h1 class="mt-2 text-2xl font-black tracking-tight text-[#800000] md:text-3xl">
            Student Enrollment
          </h1>

          <p class="mt-1 max-w-2xl text-sm font-medium text-[#6B7280]">
            Enroll students into subjects and manage active subject enrollment records.
          </p>
        </div>

        <div
          class="inline-flex w-fit rounded-full border border-[#E7DCC3] bg-white px-4 py-2 text-xs font-bold text-[#800000] shadow-sm"
        >
          {{ filteredEnrollments.length }} enrollment{{ filteredEnrollments.length === 1 ? '' : 's' }}
        </div>
      </div>
    </section>

    <section class="grid grid-cols-1 gap-6 xl:grid-cols-12">
      <!-- Enrollment Form -->
      <aside class="xl:col-span-4">
        <div
          class="sticky top-28 rounded-[28px] border border-[#E7DCC3] bg-white p-6 shadow-sm"
        >
          <div class="mb-5 flex items-center gap-3">
            <div
              class="flex h-11 w-11 items-center justify-center rounded-2xl bg-[#FFF8E1] text-[#800000] ring-1 ring-[#E7DCC3]"
            >
              <UserPlusIcon class="h-5 w-5" />
            </div>

            <div>
              <h2 class="text-base font-black text-[#1F2937]">
                Enroll Student
              </h2>
              <p class="text-xs text-[#6B7280]">
                Select a student and assign a subject.
              </p>
            </div>
          </div>

          <div class="space-y-4">
            <div class="space-y-1.5">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#1F2937]">
                Student
              </label>

              <select
                v-model="selectedStudentId"
                class="w-full cursor-pointer rounded-[12px] border border-[#E7DCC3] bg-white px-4 py-3 text-sm text-[#1F2937] outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
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

              <p v-if="students.length === 0" class="text-xs font-medium text-red-600">
                No student records found.
              </p>
            </div>

            <div class="space-y-1.5">
              <label class="text-[11px] font-bold uppercase tracking-wider text-[#1F2937]">
                Subject
              </label>

              <select
                v-model="selectedSubjectId"
                class="w-full cursor-pointer rounded-[12px] border border-[#E7DCC3] bg-white px-4 py-3 text-sm text-[#1F2937] outline-none transition focus:border-[#800000] focus:ring-2 focus:ring-[#F6E7B2]"
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

              <p v-if="subjects.length === 0" class="text-xs font-medium text-red-600">
                No subjects found. Add subjects first.
              </p>
            </div>

            <button
              @click="processEnrollment"
              :disabled="enrolling"
              class="inline-flex w-full items-center justify-center gap-2 rounded-full bg-[#800000] px-5 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-[#5A0000] disabled:cursor-not-allowed disabled:opacity-60"
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
        <section
          class="flex flex-col justify-between gap-4 rounded-[24px] border border-[#E7DCC3] bg-white p-4 shadow-sm md:flex-row md:items-center"
        >
          <div
            class="flex w-full items-center rounded-full border border-[#E7DCC3] bg-[#FAFAF7] px-4 py-2.5 transition focus-within:border-[#800000] focus-within:bg-white focus-within:ring-2 focus-within:ring-[#F6E7B2] md:max-w-md"
          >
            <SearchIcon class="mr-2 h-4 w-4 shrink-0 text-[#800000]/70" />
            <input
              v-model="searchQuery"
              type="text"
              placeholder="Search by student, subject code, or subject title..."
              class="w-full bg-transparent text-sm font-medium text-[#1F2937] outline-none placeholder:text-[#9CA3AF]"
            />
          </div>

          <button
            @click="fetchData"
            class="inline-flex w-fit items-center gap-2 rounded-full border border-[#E7DCC3] bg-white px-4 py-2 text-xs font-bold text-[#800000] transition hover:bg-[#FFF8E1]"
          >
            <RefreshCcwIcon class="h-3.5 w-3.5" />
            Refresh
          </button>
        </section>

        <!-- Main Card -->
        <section class="overflow-hidden rounded-[28px] border border-[#E7DCC3] bg-white shadow-sm">
          <div v-if="loading" class="p-12 text-center">
            <span
              class="inline-block h-7 w-7 animate-spin rounded-full border-2 border-[#800000] border-t-transparent"
            ></span>
            <p class="mt-3 text-sm font-bold text-[#6B7280]">
              Loading enrollment records...
            </p>
          </div>

          <div v-else-if="error" class="p-12 text-center">
            <AlertCircleIcon class="mx-auto h-10 w-10 text-red-600" />
            <p class="mt-3 text-sm font-bold text-red-600">
              {{ error }}
            </p>
          </div>

          <div v-else-if="filteredEnrollments.length === 0" class="p-12 text-center">
            <div
              class="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-[#FFF8E1] text-[#800000]"
            >
              <UsersIcon class="h-7 w-7" />
            </div>

            <h2 class="mt-4 text-lg font-black text-[#1F2937]">
              No enrollment records found
            </h2>

            <p class="mt-1 text-sm text-[#6B7280]">
              Enroll a student into a subject to create a record.
            </p>
          </div>

          <div v-else class="divide-y divide-[#E7DCC3]/70">
            <!-- Desktop Header -->
            <div
              class="hidden grid-cols-12 gap-4 bg-[#FAFAF7] px-6 py-4 text-xs font-black uppercase tracking-wider text-[#6B7280] lg:grid"
            >
              <div class="col-span-4">Student</div>
              <div class="col-span-5">Subject</div>
              <div class="col-span-3 text-right">Action</div>
            </div>

            <div
              v-for="enrollment in filteredEnrollments"
              :key="enrollment.id"
              class="grid grid-cols-1 gap-4 px-6 py-5 transition hover:bg-[#FAFAF7] lg:grid-cols-12 lg:items-center"
            >
              <!-- Student -->
              <div class="min-w-0 lg:col-span-4">
                <div class="flex items-center gap-3">
                  <div
                    class="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[#800000] to-[#5A0000] text-xs font-black text-white ring-2 ring-[#D4AF37]/40"
                  >
                    {{ getInitials(enrollment.studentName) }}
                  </div>

                  <div class="min-w-0">
                    <p class="truncate text-sm font-black text-[#1F2937]">
                      {{ enrollment.studentName || 'Student' }}
                    </p>
                    <p class="mt-0.5 truncate text-xs font-medium text-[#6B7280]">
                      {{ enrollment.studentEmail || 'No email' }}
                    </p>
                  </div>
                </div>
              </div>

              <!-- Subject -->
              <div class="min-w-0 lg:col-span-5">
                <span
                  class="mb-1 inline-flex rounded-full border border-[#E7DCC3] bg-[#FFF8E1] px-3 py-1 text-[10px] font-black uppercase tracking-wider text-[#800000]"
                >
                  {{ enrollment.subjectCode || 'Subject' }}
                </span>

                <p class="truncate text-sm font-black text-[#1F2937]">
                  {{ enrollment.subjectTitle || 'Untitled Subject' }}
                </p>

                <p class="mt-0.5 truncate text-xs text-[#6B7280]">
                  Instructor: {{ enrollment.instructorName || 'Unassigned' }}
                </p>
              </div>

              <!-- Action -->
              <div class="lg:col-span-3 lg:text-right">
                <button
                  @click="revokeEnrollment(enrollment.id)"
                  class="inline-flex w-full items-center justify-center gap-2 rounded-full border border-red-200 bg-red-50 px-4 py-2 text-xs font-black text-red-600 shadow-sm transition hover:bg-red-600 hover:text-white lg:w-auto"
                >
                  <Trash2Icon class="h-3.5 w-3.5" />
                  Remove
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
import { computed, onMounted, ref } from 'vue'
import {
  addDoc,
  collection,
  deleteDoc,
  doc,
  getDocs,
  query,
  serverTimestamp,
  where,
} from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import {
  AlertCircleIcon,
  LinkIcon,
  RefreshCcwIcon,
  SearchIcon,
  Trash2Icon,
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

const selectedStudentId = ref('')
const selectedSubjectId = ref('')

const filteredEnrollments = computed(() => {
  const keyword = searchQuery.value.toLowerCase().trim()

  if (!keyword) return enrollments.value

  return enrollments.value.filter((enrollment) => {
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
    }))

    const subjectSnapshot = await getDocs(collection(db, 'subjects'))

    subjects.value = subjectSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))

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
    alert('Please select a student and a subject.')
    return
  }

  const alreadyEnrolled = enrollments.value.some((enrollment) => {
    return (
      enrollment.studentId === selectedStudentId.value &&
      enrollment.subjectId === selectedSubjectId.value
    )
  })

  if (alreadyEnrolled) {
    alert('This student is already enrolled in the selected subject.')
    return
  }

  const selectedStudent = students.value.find(
    (student) => student.id === selectedStudentId.value
  )

  const selectedSubject = subjects.value.find(
    (subject) => subject.id === selectedSubjectId.value
  )

  if (!selectedStudent || !selectedSubject) {
    alert('Selected student or subject was not found.')
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
  } catch (err) {
    console.error('Process enrollment error:', err)
    alert('Unable to enroll student. Please try again.')
  } finally {
    enrolling.value = false
  }
}

async function revokeEnrollment(id) {
  if (!confirm('Remove this student from the subject?')) return

  try {
    await deleteDoc(doc(db, 'enrollments', id))
    await fetchData()
  } catch (err) {
    console.error('Revoke enrollment error:', err)
    alert('Unable to remove enrollment record.')
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
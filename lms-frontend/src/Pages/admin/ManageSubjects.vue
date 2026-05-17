<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import {
  addDoc,
  collection,
  deleteDoc,
  doc,
  getDocs,
  orderBy,
  query,
  serverTimestamp,
  updateDoc,
} from 'firebase/firestore'
import { db } from '../../firebase/config.js'

const COLLECTION_NAME = 'redesigned_subjects'

const emptyForm = () => ({
  code: '',
  title: '',
  description: '',
  instructorName: '',
  department: '',
  specialization: '',
  courseName: '',
  moduleTitle: '',
  activityTitle: '',
  studentName: '',
})

const sampleSubjects = [
  {
    code: 'CCC101',
    title: 'Intro to Programming',
    description: 'Basics',
    instructor: {
      name: 'Amer Hussien Macatotong',
      department: 'Information Systems',
      specialization: 'Database',
    },
    course: {
      courseName: 'BS Information Technology',
    },
    modules: [
      {
        title: 'Lecture 1',
        description: 'Slides',
        fileKey: 'gcs/dummy/lec1.pdf',
        uploadedAt: '2025-12-08',
      },
      {
        title: 'Module 1',
        description: 'Introduction to DB',
        fileKey: '',
        uploadedAt: '2025-10-12',
      },
    ],
    activities: [
      {
        title: 'Essay 1',
        description: 'Write a 300-word essay.',
        type: 'assignment',
        maxScore: 100,
        dueDate: '2025-01-15',
      },
    ],
    enrolledStudents: [
      {
        name: 'Janisah A. Macarimbang',
        studentNumber: '202227914',
        program: 'BS-IT',
        yearLevel: '3rd Year',
      },
    ],
  },
  {
    code: 'CCC102',
    title: 'Intro',
    description: 'Prog 2',
    instructor: {
      name: 'Dr. Santos',
      department: 'Computer Studies',
      specialization: 'Web Development',
    },
    course: {
      courseName: 'BS Information Technology',
    },
    modules: [
      {
        title: 'Lecture 1',
        description: 'Slides',
        fileKey: 'gcs/dummy/lec1.pdf',
        uploadedAt: '2025-12-09',
      },
      {
        title: 'Mayma',
        description: 'HUHU',
        fileKey: null,
        uploadedAt: '2025-12-10',
      },
      {
        title: 'JJ',
        description: 'HAHA',
        fileKey: null,
        uploadedAt: '2025-12-10',
      },
    ],
    activities: [
      {
        title: 'Act 1',
        description: '',
        type: 'assignment',
        maxScore: 100,
        dueDate: '',
      },
      {
        title: 'Assignment2',
        description: 'Make a query',
        type: 'quiz',
        maxScore: 100,
        dueDate: '',
      },
    ],
    enrolledStudents: [
      {
        name: 'Test Student',
        studentNumber: 'S2025-001',
        program: 'BSIT',
        yearLevel: '1st Year',
      },
    ],
  },
  {
    code: 'ITD114',
    title: 'Information Management',
    description: 'SQL and NoSQL database concepts',
    instructor: {
      name: 'Amer Hussien Macatotong',
      department: 'Information Systems',
      specialization: 'Database',
    },
    course: {
      courseName: 'BS Information Technology',
    },
    modules: [
      {
        title: 'SQL Fundamentals',
        description: 'Introduction to relational databases',
        fileKey: '',
        uploadedAt: '2026-05-16',
      },
      {
        title: 'NoSQL Redesign Concepts',
        description: 'Document database redesign principles',
        fileKey: '',
        uploadedAt: '2026-05-16',
      },
    ],
    activities: [
      {
        title: 'SQL to NoSQL Redesign Project',
        description: 'Redesign an SQL database into Firebase Firestore.',
        type: 'project',
        maxScore: 100,
        dueDate: '2026-05-25',
      },
    ],
    enrolledStudents: [
      {
        name: 'Janisah A. Macarimbang',
        studentNumber: '202227914',
        program: 'BS-IT',
        yearLevel: '3rd Year',
      },
      {
        name: 'Test Student',
        studentNumber: '2025-0010',
        program: 'BSIT',
        yearLevel: '1st Year',
      },
    ],
  },
  {
    code: 'ITD112',
    title: 'Web Systems and Technologies',
    description: 'Frontend and Firebase Firestore development',
    instructor: {
      name: 'Dr. Santos',
      department: 'Computer Studies',
      specialization: 'Web Development',
    },
    course: {
      courseName: 'BS Information Technology',
    },
    modules: [
      {
        title: 'Vue Basics',
        description: 'Vue 3 Composition API introduction',
        fileKey: '',
        uploadedAt: '2026-05-16',
      },
      {
        title: 'Firebase Firestore CRUD',
        description: 'Using Firestore as NoSQL database',
        fileKey: '',
        uploadedAt: '2026-05-16',
      },
    ],
    activities: [
      {
        title: 'Build a CRUD App',
        description: 'Create a working CRUD app using Firebase.',
        type: 'project',
        maxScore: 100,
        dueDate: '2026-05-30',
      },
    ],
    enrolledStudents: [
      {
        name: 'Test Student',
        studentNumber: 'S2025-001',
        program: 'BSIT',
        yearLevel: '1st Year',
      },
    ],
  },
]

const subjects = ref([])
const form = reactive(emptyForm())
const editingId = ref(null)
const selectedSubject = ref(null)
const isLoading = ref(false)
const isSaving = ref(false)
const feedback = ref('')
const errorMessage = ref('')

const formTitle = computed(() => (editingId.value ? 'Update Subject' : 'Create Subject'))
const submitText = computed(() => (editingId.value ? 'Save Changes' : 'Add Subject'))

const stats = computed(() => ({
  totalSubjects: subjects.value.length,
  totalModules: subjects.value.reduce((sum, subject) => sum + (subject.modules?.length || 0), 0),
  totalActivities: subjects.value.reduce((sum, subject) => sum + (subject.activities?.length || 0), 0),
  totalEnrolledStudents: subjects.value.reduce(
    (sum, subject) => sum + (subject.enrolledStudents?.length || 0),
    0,
  ),
}))

const subjectCollection = () => collection(db, COLLECTION_NAME)

const loadSubjects = async () => {
  isLoading.value = true
  errorMessage.value = ''

  try {
    const subjectQuery = query(subjectCollection(), orderBy('createdAt', 'desc'))
    const snapshot = await getDocs(subjectQuery)

    subjects.value = snapshot.docs.map((subjectDoc) => ({
      id: subjectDoc.id,
      ...subjectDoc.data(),
    }))
  } catch (error) {
    errorMessage.value = `Unable to load Firebase Firestore subjects: ${error.message}`
  } finally {
    isLoading.value = false
  }
}

const resetForm = () => {
  Object.assign(form, emptyForm())
  editingId.value = null
}

const buildSubjectPayload = () => ({
  code: form.code.trim(),
  title: form.title.trim(),
  description: form.description.trim(),
  instructor: {
    name: form.instructorName.trim(),
    department: form.department.trim(),
    specialization: form.specialization.trim(),
  },
  course: {
    courseName: form.courseName.trim(),
  },
  modules: form.moduleTitle.trim() ? [{ title: form.moduleTitle.trim() }] : [],
  activities: form.activityTitle.trim() ? [{ title: form.activityTitle.trim() }] : [],
  enrolledStudents: form.studentName.trim() ? [{ name: form.studentName.trim() }] : [],
})

const saveSubject = async () => {
  errorMessage.value = ''
  feedback.value = ''

  if (!form.code.trim() || !form.title.trim()) {
    errorMessage.value = 'Subject Code and Subject Title are required.'
    return
  }

  isSaving.value = true

  try {
    const payload = buildSubjectPayload()

    if (editingId.value) {
      await updateDoc(doc(db, COLLECTION_NAME, editingId.value), {
        ...payload,
        updatedAt: serverTimestamp(),
      })
      feedback.value = 'Subject updated in Firebase Firestore.'
    } else {
      await addDoc(subjectCollection(), {
        ...payload,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      })
      feedback.value = 'Subject added to the NoSQL redesigned collection.'
    }

    resetForm()
    await loadSubjects()
  } catch (error) {
    errorMessage.value = `Unable to save subject: ${error.message}`
  } finally {
    isSaving.value = false
  }
}

const editSubject = (subject) => {
  editingId.value = subject.id
  form.code = subject.code || ''
  form.title = subject.title || ''
  form.description = subject.description || ''
  form.instructorName = subject.instructor?.name || ''
  form.department = subject.instructor?.department || ''
  form.specialization = subject.instructor?.specialization || ''
  form.courseName = subject.course?.courseName || ''
  form.moduleTitle = subject.modules?.[0]?.title || ''
  form.activityTitle = subject.activities?.[0]?.title || ''
  form.studentName = subject.enrolledStudents?.[0]?.name || ''
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

const deleteSubject = async (subject) => {
  const confirmed = window.confirm(`Delete ${subject.code} - ${subject.title} from Firebase Firestore?`)

  if (!confirmed) return

  errorMessage.value = ''
  feedback.value = ''

  try {
    await deleteDoc(doc(db, COLLECTION_NAME, subject.id))
    feedback.value = 'Subject deleted from Firebase Firestore.'
    if (selectedSubject.value?.id === subject.id) selectedSubject.value = null
    await loadSubjects()
  } catch (error) {
    errorMessage.value = `Unable to delete subject: ${error.message}`
  }
}

const seedSampleDataset = async () => {
  errorMessage.value = ''
  feedback.value = ''

  try {
    const snapshot = await getDocs(subjectCollection())

    if (!snapshot.empty) {
      window.alert('The sample dataset already exists in Firebase Firestore.')
      return
    }

    await Promise.all(
      sampleSubjects.map((subject) =>
        addDoc(subjectCollection(), {
          ...subject,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        }),
      ),
    )

    feedback.value = 'Sample dataset seeded into the NoSQL redesigned collection.'
    await loadSubjects()
  } catch (error) {
    errorMessage.value = `Unable to seed sample dataset: ${error.message}`
  }
}

const showDetails = (subject) => {
  selectedSubject.value = selectedSubject.value?.id === subject.id ? null : subject
}

onMounted(loadSubjects)
</script>

<template>
  <div class="min-h-screen bg-[#FFF8E7] text-[#1F1F1F]">
    <div class="mx-auto max-w-7xl space-y-8 p-4 sm:p-6 lg:p-8">
      <header class="rounded-2xl border border-[#E7DCC3] bg-white p-6 shadow-sm">
        <div class="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p class="text-sm font-semibold uppercase tracking-[0.24em] text-[#800000]">
              MSU Main Learning Management System
            </p>
            <h1 class="mt-2 text-3xl font-bold text-[#1F1F1F]">Manage Subjects</h1>
            <p class="mt-2 max-w-3xl text-sm leading-6 text-[#6B7280]">
              Firebase Firestore CRUD for the SQL to NoSQL redesigned LMS.
            </p>
          </div>

          <button
            type="button"
            class="rounded-2xl bg-[#800000] px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-[#5A0000] focus:outline-none focus:ring-2 focus:ring-[#D4AF37] focus:ring-offset-2"
            @click="seedSampleDataset"
          >
            Seed Sample Dataset
          </button>
        </div>
      </header>

      <section class="rounded-2xl border border-[#E7DCC3] bg-white p-6 shadow-sm">
        <div class="flex gap-4">
          <div class="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-[#800000] text-lg font-bold text-[#D4AF37]">
            DB
          </div>
          <div>
            <h2 class="text-lg font-bold text-[#1F1F1F]">NoSQL redesign note</h2>
            <p class="mt-2 text-sm leading-7 text-[#6B7280]">
              “The original SQL LMS stored subjects, modules, activities, and enrollments in
              separate tables. In the Firestore redesign, these related records are embedded
              inside each subject document to reduce relational joins and make subject-centered
              data easier to retrieve.”
            </p>
          </div>
        </div>
      </section>

      <section class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <article class="rounded-2xl border border-[#E7DCC3] bg-white p-5 shadow-sm">
          <p class="text-sm font-semibold text-[#6B7280]">Total Subjects</p>
          <p class="mt-2 text-3xl font-bold text-[#800000]">{{ stats.totalSubjects }}</p>
        </article>
        <article class="rounded-2xl border border-[#E7DCC3] bg-white p-5 shadow-sm">
          <p class="text-sm font-semibold text-[#6B7280]">Total Modules</p>
          <p class="mt-2 text-3xl font-bold text-[#800000]">{{ stats.totalModules }}</p>
        </article>
        <article class="rounded-2xl border border-[#E7DCC3] bg-white p-5 shadow-sm">
          <p class="text-sm font-semibold text-[#6B7280]">Total Activities</p>
          <p class="mt-2 text-3xl font-bold text-[#800000]">{{ stats.totalActivities }}</p>
        </article>
        <article class="rounded-2xl border border-[#E7DCC3] bg-white p-5 shadow-sm">
          <p class="text-sm font-semibold text-[#6B7280]">Total Enrolled Students</p>
          <p class="mt-2 text-3xl font-bold text-[#800000]">{{ stats.totalEnrolledStudents }}</p>
        </article>
      </section>

      <div v-if="feedback" class="rounded-2xl border border-[#D4AF37] bg-[#FFF8E7] p-4 text-sm font-semibold text-[#5A0000]">
        {{ feedback }}
      </div>
      <div v-if="errorMessage" class="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm font-semibold text-red-700">
        {{ errorMessage }}
      </div>

      <section class="grid gap-8 xl:grid-cols-[420px_1fr]">
        <form class="rounded-2xl border border-[#E7DCC3] bg-white p-6 shadow-sm" @submit.prevent="saveSubject">
          <div class="mb-6 border-b border-[#E7DCC3] pb-4">
            <h2 class="text-xl font-bold text-[#1F1F1F]">{{ formTitle }}</h2>
            <p class="mt-1 text-sm text-[#6B7280]">
              Store subject-centered records in the redesigned_subjects Firestore collection.
            </p>
          </div>

          <div class="space-y-4">
            <label class="block">
              <span class="text-sm font-semibold text-[#1F1F1F]">Subject Code</span>
              <input v-model="form.code" type="text" class="mt-1 w-full rounded-xl border border-[#E7DCC3] bg-[#FFF8E7] px-4 py-3 text-sm outline-none focus:border-[#800000] focus:ring-2 focus:ring-[#D4AF37]/40" placeholder="CCC101" />
            </label>

            <label class="block">
              <span class="text-sm font-semibold text-[#1F1F1F]">Subject Title</span>
              <input v-model="form.title" type="text" class="mt-1 w-full rounded-xl border border-[#E7DCC3] bg-[#FFF8E7] px-4 py-3 text-sm outline-none focus:border-[#800000] focus:ring-2 focus:ring-[#D4AF37]/40" placeholder="Intro to Programming" />
            </label>

            <label class="block">
              <span class="text-sm font-semibold text-[#1F1F1F]">Description</span>
              <textarea v-model="form.description" rows="3" class="mt-1 w-full rounded-xl border border-[#E7DCC3] bg-[#FFF8E7] px-4 py-3 text-sm outline-none focus:border-[#800000] focus:ring-2 focus:ring-[#D4AF37]/40" placeholder="Subject overview"></textarea>
            </label>

            <div class="grid gap-4 sm:grid-cols-2">
              <label class="block sm:col-span-2">
                <span class="text-sm font-semibold text-[#1F1F1F]">Instructor Name</span>
                <input v-model="form.instructorName" type="text" class="mt-1 w-full rounded-xl border border-[#E7DCC3] bg-[#FFF8E7] px-4 py-3 text-sm outline-none focus:border-[#800000] focus:ring-2 focus:ring-[#D4AF37]/40" placeholder="Instructor name" />
              </label>

              <label class="block">
                <span class="text-sm font-semibold text-[#1F1F1F]">Department</span>
                <input v-model="form.department" type="text" class="mt-1 w-full rounded-xl border border-[#E7DCC3] bg-[#FFF8E7] px-4 py-3 text-sm outline-none focus:border-[#800000] focus:ring-2 focus:ring-[#D4AF37]/40" placeholder="Computer Studies" />
              </label>

              <label class="block">
                <span class="text-sm font-semibold text-[#1F1F1F]">Specialization</span>
                <input v-model="form.specialization" type="text" class="mt-1 w-full rounded-xl border border-[#E7DCC3] bg-[#FFF8E7] px-4 py-3 text-sm outline-none focus:border-[#800000] focus:ring-2 focus:ring-[#D4AF37]/40" placeholder="Web Development" />
              </label>
            </div>

            <label class="block">
              <span class="text-sm font-semibold text-[#1F1F1F]">Course Name</span>
              <input v-model="form.courseName" type="text" class="mt-1 w-full rounded-xl border border-[#E7DCC3] bg-[#FFF8E7] px-4 py-3 text-sm outline-none focus:border-[#800000] focus:ring-2 focus:ring-[#D4AF37]/40" placeholder="BS Information Technology" />
            </label>

            <div class="rounded-2xl border border-[#E7DCC3] bg-[#FFF8E7] p-4">
              <p class="text-sm font-bold text-[#800000]">Optional embedded records</p>
              <div class="mt-4 space-y-4">
                <label class="block">
                  <span class="text-sm font-semibold text-[#1F1F1F]">Module Title</span>
                  <input v-model="form.moduleTitle" type="text" class="mt-1 w-full rounded-xl border border-[#E7DCC3] bg-white px-4 py-3 text-sm outline-none focus:border-[#800000] focus:ring-2 focus:ring-[#D4AF37]/40" placeholder="Lecture 1" />
                </label>
                <label class="block">
                  <span class="text-sm font-semibold text-[#1F1F1F]">Activity Title</span>
                  <input v-model="form.activityTitle" type="text" class="mt-1 w-full rounded-xl border border-[#E7DCC3] bg-white px-4 py-3 text-sm outline-none focus:border-[#800000] focus:ring-2 focus:ring-[#D4AF37]/40" placeholder="Essay 1" />
                </label>
                <label class="block">
                  <span class="text-sm font-semibold text-[#1F1F1F]">Enrolled Student Name</span>
                  <input v-model="form.studentName" type="text" class="mt-1 w-full rounded-xl border border-[#E7DCC3] bg-white px-4 py-3 text-sm outline-none focus:border-[#800000] focus:ring-2 focus:ring-[#D4AF37]/40" placeholder="Student name" />
                </label>
              </div>
            </div>
          </div>

          <div class="mt-6 flex flex-col gap-3 sm:flex-row">
            <button type="submit" class="rounded-2xl bg-[#800000] px-5 py-3 text-sm font-semibold text-white transition hover:bg-[#5A0000] disabled:cursor-not-allowed disabled:opacity-70" :disabled="isSaving">
              {{ isSaving ? 'Saving...' : submitText }}
            </button>
            <button v-if="editingId" type="button" class="rounded-2xl border border-[#E7DCC3] px-5 py-3 text-sm font-semibold text-[#800000] transition hover:bg-[#FFF8E7]" @click="resetForm">
              Cancel Edit
            </button>
          </div>
        </form>

        <section class="space-y-4">
          <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h2 class="text-xl font-bold text-[#1F1F1F]">Subject Documents</h2>
              <p class="text-sm text-[#6B7280]">Cards are loaded from Firebase Firestore.</p>
            </div>
            <button type="button" class="rounded-2xl border border-[#E7DCC3] bg-white px-4 py-2 text-sm font-semibold text-[#800000] transition hover:bg-[#FFF8E7]" @click="loadSubjects">
              Refresh List
            </button>
          </div>

          <div v-if="isLoading" class="rounded-2xl border border-[#E7DCC3] bg-white p-6 text-center text-sm font-semibold text-[#6B7280] shadow-sm">
            Loading Firebase Firestore subjects...
          </div>

          <div v-else-if="subjects.length === 0" class="rounded-2xl border border-dashed border-[#E7DCC3] bg-white p-8 text-center shadow-sm">
            <p class="text-lg font-bold text-[#1F1F1F]">No subject documents yet.</p>
            <p class="mt-2 text-sm text-[#6B7280]">Create a subject or seed the sample dataset.</p>
          </div>

          <template v-else>
            <article v-for="subject in subjects" :key="subject.id" class="rounded-2xl border border-[#E7DCC3] bg-white p-6 shadow-sm">
            <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <div class="flex flex-wrap items-center gap-2">
                  <span class="rounded-full bg-[#800000] px-3 py-1 text-xs font-bold uppercase tracking-wide text-white">
                    {{ subject.code }}
                  </span>
                  <span class="rounded-full border border-[#D4AF37] px-3 py-1 text-xs font-bold uppercase tracking-wide text-[#5A0000]">
                    {{ subject.course?.courseName || 'No course' }}
                  </span>
                </div>
                <h3 class="mt-3 text-xl font-bold text-[#1F1F1F]">{{ subject.title }}</h3>
                <p class="mt-2 text-sm leading-6 text-[#6B7280]">{{ subject.description || 'No description provided.' }}</p>
              </div>

              <div class="flex flex-wrap gap-2">
                <button type="button" class="rounded-xl border border-[#E7DCC3] px-3 py-2 text-xs font-bold text-[#800000] transition hover:bg-[#FFF8E7]" @click="showDetails(subject)">
                  View Details
                </button>
                <button type="button" class="rounded-xl border border-[#D4AF37] px-3 py-2 text-xs font-bold text-[#5A0000] transition hover:bg-[#FFF8E7]" @click="editSubject(subject)">
                  Edit
                </button>
                <button type="button" class="rounded-xl bg-[#5A0000] px-3 py-2 text-xs font-bold text-white transition hover:bg-[#800000]" @click="deleteSubject(subject)">
                  Delete
                </button>
              </div>
            </div>

            <div class="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              <div class="rounded-2xl bg-[#FFF8E7] p-4">
                <p class="text-xs font-bold uppercase tracking-wide text-[#6B7280]">Instructor</p>
                <p class="mt-1 font-semibold text-[#1F1F1F]">{{ subject.instructor?.name || 'Unassigned' }}</p>
                <p class="text-sm text-[#6B7280]">{{ subject.instructor?.department || 'No department' }}</p>
                <p class="text-sm text-[#6B7280]">{{ subject.instructor?.specialization || 'No specialization' }}</p>
              </div>
              <div class="rounded-2xl bg-[#FFF8E7] p-4">
                <p class="text-xs font-bold uppercase tracking-wide text-[#6B7280]">Embedded Counts</p>
                <p class="mt-1 text-sm text-[#1F1F1F]">Modules: <strong>{{ subject.modules?.length || 0 }}</strong></p>
                <p class="text-sm text-[#1F1F1F]">Activities: <strong>{{ subject.activities?.length || 0 }}</strong></p>
                <p class="text-sm text-[#1F1F1F]">Enrolled Students: <strong>{{ subject.enrolledStudents?.length || 0 }}</strong></p>
              </div>
              <div class="rounded-2xl bg-[#FFF8E7] p-4 md:col-span-2 xl:col-span-1">
                <p class="text-xs font-bold uppercase tracking-wide text-[#6B7280]">Collection</p>
                <p class="mt-1 font-semibold text-[#800000]">{{ COLLECTION_NAME }}</p>
                <p class="text-sm text-[#6B7280]">NoSQL redesigned collection</p>
              </div>
            </div>

            <div v-if="selectedSubject?.id === subject.id" class="mt-5 rounded-2xl border border-[#E7DCC3] bg-[#FFF8E7] p-5">
              <h4 class="text-lg font-bold text-[#1F1F1F]">Subject Details</h4>
              <div class="mt-4 grid gap-4 lg:grid-cols-3">
                <div>
                  <p class="font-bold text-[#800000]">Modules</p>
                  <ul class="mt-2 space-y-2 text-sm text-[#1F1F1F]">
                    <li v-for="(module, index) in subject.modules" :key="`module-${index}`" class="rounded-xl bg-white p-3">
                      <strong>{{ module.title || 'Untitled module' }}</strong>
                      <p v-if="module.description" class="text-[#6B7280]">{{ module.description }}</p>
                      <p v-if="module.uploadedAt" class="text-xs text-[#6B7280]">Uploaded: {{ module.uploadedAt }}</p>
                    </li>
                    <li v-if="!subject.modules?.length" class="rounded-xl bg-white p-3 text-[#6B7280]">No modules embedded.</li>
                  </ul>
                </div>

                <div>
                  <p class="font-bold text-[#800000]">Activities</p>
                  <ul class="mt-2 space-y-2 text-sm text-[#1F1F1F]">
                    <li v-for="(activity, index) in subject.activities" :key="`activity-${index}`" class="rounded-xl bg-white p-3">
                      <strong>{{ activity.title || 'Untitled activity' }}</strong>
                      <p v-if="activity.description" class="text-[#6B7280]">{{ activity.description }}</p>
                      <p class="text-xs text-[#6B7280]">
                        {{ activity.type || 'activity' }}<span v-if="activity.maxScore"> · {{ activity.maxScore }} pts</span><span v-if="activity.dueDate"> · Due {{ activity.dueDate }}</span>
                      </p>
                    </li>
                    <li v-if="!subject.activities?.length" class="rounded-xl bg-white p-3 text-[#6B7280]">No activities embedded.</li>
                  </ul>
                </div>

                <div>
                  <p class="font-bold text-[#800000]">Enrolled Students</p>
                  <ul class="mt-2 space-y-2 text-sm text-[#1F1F1F]">
                    <li v-for="(student, index) in subject.enrolledStudents" :key="`student-${index}`" class="rounded-xl bg-white p-3">
                      <strong>{{ student.name || 'Unnamed student' }}</strong>
                      <p class="text-xs text-[#6B7280]">
                        {{ student.studentNumber || 'No student number' }}<span v-if="student.program"> · {{ student.program }}</span><span v-if="student.yearLevel"> · {{ student.yearLevel }}</span>
                      </p>
                    </li>
                    <li v-if="!subject.enrolledStudents?.length" class="rounded-xl bg-white p-3 text-[#6B7280]">No enrolled students embedded.</li>
                  </ul>
                </div>
              </div>
            </div>
            </article>
          </template>
        </section>
      </section>
    </div>
  </div>
</template>

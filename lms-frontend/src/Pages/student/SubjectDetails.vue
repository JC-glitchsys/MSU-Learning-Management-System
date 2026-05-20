<template>
  <div class="space-y-6 animate-fade-in">
    <!-- Loading -->
    <div
      v-if="loading"
      class="rounded-[28px] border border-[#E7DCC3] bg-white p-10 text-center shadow-sm"
    >
      <span class="inline-block h-7 w-7 animate-spin rounded-full border-2 border-[#800000] border-t-transparent"></span>
      <p class="mt-3 text-sm font-semibold text-[#6B7280]">Loading subject details...</p>
    </div>

    <!-- Error -->
    <div
      v-else-if="error"
      class="rounded-[28px] border border-red-200 bg-red-50 p-6 text-sm font-semibold text-red-600"
    >
      {{ error }}
    </div>

    <template v-else>
      <!-- Class Banner -->
      <section
        class="relative overflow-hidden rounded-[28px] border border-[#E7DCC3] bg-gradient-to-r from-[#800000] via-[#9A1B1B] to-[#D4AF37] p-6 text-white shadow-sm md:p-8"
      >
        <div class="absolute inset-0 bg-white/5"></div>
        <div class="absolute -right-10 -top-10 h-40 w-40 rounded-full bg-white/10"></div>
        <div class="absolute -bottom-12 left-10 h-36 w-36 rounded-full bg-black/10"></div>

        <div class="relative z-10">
          <router-link
            to="/student/subjects"
            class="mb-4 inline-flex items-center gap-2 rounded-full bg-white/10 px-4 py-2 text-xs font-bold text-white ring-1 ring-white/20 transition hover:bg-white/20"
          >
            <ArrowLeftIcon class="h-4 w-4" />
            Back to Subjects
          </router-link>

          <p class="text-xs font-bold uppercase tracking-[0.25em] text-white/70">
            {{ subject.code || 'Subject' }}
          </p>

          <h1 class="mt-2 text-2xl font-black tracking-tight md:text-4xl">
            {{ subject.title || 'Untitled Subject' }}
          </h1>

          <p class="mt-2 max-w-3xl text-sm font-medium text-white/85 md:text-base">
            {{ subject.program || 'Program not specified' }}
            <span v-if="subject.section"> • {{ subject.section }}</span>
            <span v-if="subject.instructorName"> • {{ subject.instructorName }}</span>
          </p>

          <p v-if="subject.description" class="mt-4 max-w-3xl text-sm leading-relaxed text-white/80">
            {{ subject.description }}
          </p>
        </div>
      </section>

      <!-- Tabs -->
      <div class="sticky top-24 z-10 rounded-full border border-[#E7DCC3] bg-white/90 p-1 shadow-sm backdrop-blur">
        <div class="flex gap-1 overflow-x-auto">
          <button
            v-for="tab in tabs"
            :key="tab.key"
            @click="currentTab = tab.key"
            :class="
              currentTab === tab.key
                ? 'bg-[#800000] text-white shadow-sm'
                : 'text-[#6B7280] hover:bg-[#FFF8E1] hover:text-[#800000]'
            "
            class="inline-flex items-center gap-2 rounded-full px-5 py-2 text-sm font-bold transition"
          >
            <component :is="tab.icon" class="h-4 w-4" />
            {{ tab.label }}
          </button>
        </div>
      </div>

      <!-- Stream -->
      <section v-if="currentTab === 'stream'" class="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <aside class="lg:col-span-4 xl:col-span-3">
          <div class="rounded-[24px] border border-[#E7DCC3] bg-gradient-to-br from-white to-[#FFF8E1] p-5 shadow-sm">
            <h2 class="text-sm font-black text-[#1F2937]">Upcoming Activities</h2>

            <div v-if="pendingActivities.length === 0" class="mt-4 text-sm text-[#6B7280]">
              No pending activities for this subject.
            </div>

            <div v-else class="mt-4 space-y-3">
              <div
                v-for="activity in pendingActivities.slice(0, 3)"
                :key="activity.id"
                class="rounded-2xl border border-[#E7DCC3] bg-white p-4"
              >
                <p class="text-sm font-bold text-[#1F2937]">{{ activity.title }}</p>
                <p class="mt-1 text-xs text-[#6B7280]">
                  Due: {{ formatDate(activity.dueDate) }}
                </p>
              </div>
            </div>
          </div>
        </aside>

        <main class="space-y-4 lg:col-span-8 xl:col-span-9">
          <div class="rounded-[24px] border border-[#E7DCC3] bg-white p-5 shadow-sm">
            <div class="flex items-center gap-3">
              <div class="flex h-10 w-10 items-center justify-center rounded-full bg-[#800000] text-xs font-bold text-white">
                {{ instructorInitials }}
              </div>

              <div>
                <p class="text-sm font-black text-[#1F2937]">
                  {{ subject.instructorName || 'Instructor' }}
                </p>
                <p class="text-xs text-[#6B7280]">
                  Welcome to this class. Check the Classwork tab for modules and activities.
                </p>
              </div>
            </div>
          </div>

          <div
            v-if="modules.length === 0 && activities.length === 0"
            class="rounded-[24px] border border-dashed border-[#E7DCC3] bg-white p-10 text-center shadow-sm"
          >
            <p class="text-sm font-bold text-[#1F2937]">No class updates yet.</p>
            <p class="mt-1 text-xs text-[#6B7280]">
              Modules and activities posted by the instructor will appear here.
            </p>
          </div>

          <div
            v-for="item in streamItems"
            :key="item.key"
            class="rounded-[24px] border border-[#E7DCC3] bg-white p-5 shadow-sm transition hover:border-[#D4AF37]"
          >
            <div class="flex items-start gap-3">
              <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#FFF8E1] text-[#800000] ring-1 ring-[#E7DCC3]">
                <component :is="item.icon" class="h-5 w-5" />
              </div>

              <div class="min-w-0 flex-1">
                <p class="text-sm font-black text-[#1F2937]">
                  {{ item.title }}
                </p>
                <p class="mt-1 text-xs font-medium text-[#6B7280]">
                  {{ item.subtitle }}
                </p>
                <p v-if="item.description" class="mt-3 text-sm leading-relaxed text-[#1F2937]">
                  {{ item.description }}
                </p>
              </div>
            </div>
          </div>
        </main>
      </section>

      <!-- Classwork -->
      <section v-if="currentTab === 'classwork'" class="mx-auto max-w-4xl space-y-6">
        <!-- Modules -->
        <div class="rounded-[28px] border border-[#E7DCC3] bg-white shadow-sm">
          <div class="border-b border-[#E7DCC3] px-6 py-5">
            <h2 class="text-lg font-black text-[#800000]">Modules</h2>
            <p class="mt-1 text-xs text-[#6B7280]">Learning materials uploaded by your instructor.</p>
          </div>

          <div v-if="modules.length === 0" class="p-8 text-center text-sm text-[#6B7280]">
            No modules uploaded yet.
          </div>

          <div v-else class="divide-y divide-[#E7DCC3]/70">
            <a
              v-for="module in modules"
              :key="module.id"
              :href="module.resourceLink || module.fileUrl || '#'"
              :target="module.resourceLink || module.fileUrl ? '_blank' : '_self'"
              class="flex items-center justify-between gap-4 p-5 transition hover:bg-[#FAFAF7]"
            >
              <div class="flex min-w-0 items-center gap-4">
                <div class="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-[#FFF8E1] text-[#800000] ring-1 ring-[#E7DCC3]">
                  <FileTextIcon class="h-5 w-5" />
                </div>

                <div class="min-w-0">
                  <p class="truncate text-sm font-black text-[#1F2937]">
                    {{ module.title || 'Untitled Module' }}
                  </p>
                  <p class="mt-1 text-xs text-[#6B7280]">
                    {{ module.type || 'Learning Material' }}
                    <span v-if="module.createdAt"> • {{ formatDate(module.createdAt) }}</span>
                  </p>
                </div>
              </div>

              <ExternalLinkIcon class="h-4 w-4 shrink-0 text-[#6B7280]" />
            </a>
          </div>
        </div>

        <!-- Activities -->
        <div class="rounded-[28px] border border-[#E7DCC3] bg-white shadow-sm">
          <div class="border-b border-[#E7DCC3] px-6 py-5">
            <h2 class="text-lg font-black text-[#800000]">Activities</h2>
            <p class="mt-1 text-xs text-[#6B7280]">Assignments and quizzes for this subject.</p>
          </div>

          <div v-if="activities.length === 0" class="p-8 text-center text-sm text-[#6B7280]">
            No activities posted yet.
          </div>

          <div v-else class="divide-y divide-[#E7DCC3]/70">
            <router-link
              v-for="activity in activities"
              :key="activity.id"
              to="/student/activities"
              class="flex items-center justify-between gap-4 p-5 transition hover:bg-[#FAFAF7]"
            >
              <div class="flex min-w-0 items-center gap-4">
                <div class="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-[#FFF8E1] text-[#800000] ring-1 ring-[#E7DCC3]">
                  <ClipboardListIcon class="h-5 w-5" />
                </div>

                <div class="min-w-0">
                  <p class="truncate text-sm font-black text-[#1F2937]">
                    {{ activity.title || 'Untitled Activity' }}
                  </p>
                  <p class="mt-1 text-xs text-[#6B7280]">
                    {{ activity.type || 'activity' }}
                    <span v-if="activity.points"> • {{ activity.points }} pts</span>
                    <span> • Due: {{ formatDate(activity.dueDate) }}</span>
                  </p>
                </div>
              </div>

              <span
                :class="hasSubmitted(activity.id) ? 'border-green-200 bg-green-50 text-green-700' : 'border-amber-200 bg-amber-50 text-amber-700'"
                class="shrink-0 rounded-full border px-3 py-1 text-[10px] font-bold uppercase tracking-wider"
              >
                {{ hasSubmitted(activity.id) ? 'Submitted' : 'Pending' }}
              </span>
            </router-link>
          </div>
        </div>
      </section>

      <!-- People -->
      <section v-if="currentTab === 'people'" class="mx-auto max-w-3xl space-y-6">
        <div class="rounded-[28px] border border-[#E7DCC3] bg-white p-6 shadow-sm">
          <h2 class="border-b border-[#E7DCC3] pb-3 text-xl font-black text-[#800000]">
            Instructor
          </h2>

          <div class="mt-5 flex items-center gap-3">
            <div class="flex h-11 w-11 items-center justify-center rounded-full bg-[#800000] text-sm font-bold text-white">
              {{ instructorInitials }}
            </div>
            <div>
              <p class="text-sm font-black text-[#1F2937]">
                {{ subject.instructorName || 'Not assigned' }}
              </p>
              <p class="text-xs text-[#6B7280]">Subject instructor</p>
            </div>
          </div>
        </div>

        <div class="rounded-[28px] border border-[#E7DCC3] bg-white p-6 shadow-sm">
          <div class="flex items-center justify-between border-b border-[#E7DCC3] pb-3">
            <h2 class="text-xl font-black text-[#800000]">Classmates</h2>
            <span class="text-xs font-bold text-[#6B7280]">{{ classmates.length }} students</span>
          </div>

          <div v-if="classmates.length === 0" class="p-8 text-center text-sm text-[#6B7280]">
            No classmates found.
          </div>

          <div v-else class="divide-y divide-[#E7DCC3]/70">
            <div
              v-for="student in classmates"
              :key="student.id"
              class="flex items-center gap-3 py-4"
            >
              <div class="flex h-9 w-9 items-center justify-center rounded-full bg-[#FFF8E1] text-xs font-bold text-[#800000] ring-1 ring-[#E7DCC3]">
                {{ getInitials(student.studentName || student.name) }}
              </div>
              <div>
                <p class="text-sm font-bold text-[#1F2937]">
                  {{ student.studentName || student.name || 'Student' }}
                </p>
                <p class="text-xs text-[#6B7280]">
                  {{ student.studentEmail || student.email || '' }}
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- Grades -->
      <section v-if="currentTab === 'grades'" class="mx-auto max-w-4xl">
        <div class="overflow-hidden rounded-[28px] border border-[#E7DCC3] bg-white shadow-sm">
          <div class="flex items-center justify-between border-b border-[#E7DCC3] bg-[#FAFAF7] px-6 py-4">
            <div>
              <h2 class="text-lg font-black text-[#800000]">Grades and Feedback</h2>
              <p class="mt-1 text-xs text-[#6B7280]">Your submissions for this subject.</p>
            </div>

            <span class="rounded-full border border-[#E7DCC3] bg-[#FFF8E1] px-3 py-1 text-xs font-bold text-[#800000]">
              Average: {{ averageGrade }}%
            </span>
          </div>

          <div v-if="submissions.length === 0" class="p-10 text-center text-sm text-[#6B7280]">
            No submissions or grades yet.
          </div>

          <div v-else class="divide-y divide-[#E7DCC3]/70">
            <div
              v-for="submission in submissions"
              :key="submission.id"
              class="p-5 transition hover:bg-[#FAFAF7]"
            >
              <div class="flex items-start justify-between gap-4">
                <div>
                  <p class="text-sm font-black text-[#1F2937]">
                    {{ submission.activityTitle || 'Activity' }}
                  </p>
                  <p class="mt-1 text-xs text-[#6B7280]">
                    Submitted: {{ formatDate(submission.submittedAt) }}
                  </p>
                  <p v-if="submission.feedback" class="mt-3 text-sm text-[#1F2937]">
                    Feedback: {{ submission.feedback }}
                  </p>
                </div>

                <div class="text-right">
                  <p class="text-base font-black text-[#800000]">
                    {{ submission.grade !== null && submission.grade !== undefined ? submission.grade : '—' }}
                  </p>
                  <span
                    :class="submission.status === 'graded' ? 'text-green-700 bg-green-50 border-green-200' : 'text-amber-700 bg-amber-50 border-amber-200'"
                    class="mt-2 inline-block rounded-full border px-3 py-1 text-[10px] font-bold uppercase tracking-wider"
                  >
                    {{ submission.status || 'submitted' }}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { collection, doc, getDoc, getDocs, query, where } from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import {
  ArrowLeftIcon,
  BookOpenIcon,
  ClipboardListIcon,
  ExternalLinkIcon,
  FileTextIcon,
  GraduationCapIcon,
  UsersIcon,
} from 'lucide-vue-next'

const route = useRoute()
const user = JSON.parse(localStorage.getItem('user') || '{}')

const currentTab = ref('stream')
const loading = ref(true)
const error = ref('')

const subject = ref({})
const modules = ref([])
const activities = ref([])
const submissions = ref([])
const classmates = ref([])

const tabs = [
  { key: 'stream', label: 'Stream', icon: BookOpenIcon },
  { key: 'classwork', label: 'Classwork', icon: ClipboardListIcon },
  { key: 'people', label: 'People', icon: UsersIcon },
  { key: 'grades', label: 'Grades', icon: GraduationCapIcon },
]

const submittedActivityIds = computed(() => {
  return submissions.value.map((submission) => submission.activityId)
})

const pendingActivities = computed(() => {
  return activities.value.filter((activity) => !submittedActivityIds.value.includes(activity.id))
})

const streamItems = computed(() => {
  const moduleItems = modules.value.map((module) => ({
    key: `module-${module.id}`,
    title: module.title || 'Untitled Module',
    subtitle: `Module posted • ${formatDate(module.createdAt)}`,
    description: module.description || '',
    icon: FileTextIcon,
    createdAtSeconds: module.createdAt?.seconds || 0,
  }))

  const activityItems = activities.value.map((activity) => ({
    key: `activity-${activity.id}`,
    title: activity.title || 'Untitled Activity',
    subtitle: `${activity.type || 'Activity'} • Due: ${formatDate(activity.dueDate)}`,
    description: activity.instructions || '',
    icon: ClipboardListIcon,
    createdAtSeconds: activity.createdAt?.seconds || 0,
  }))

  return [...moduleItems, ...activityItems].sort((a, b) => b.createdAtSeconds - a.createdAtSeconds)
})

const instructorInitials = computed(() => {
  return getInitials(subject.value.instructorName || 'Instructor')
})

const averageGrade = computed(() => {
  const graded = submissions.value
    .map((submission) => Number(submission.grade))
    .filter((grade) => !Number.isNaN(grade))

  if (graded.length === 0) return 0

  const sum = graded.reduce((acc, grade) => acc + grade, 0)
  return Math.round(sum / graded.length)
})

async function fetchSubjectDetails() {
  const subjectId = route.params.id

  if (!subjectId) {
    error.value = 'Subject ID was not found.'
    loading.value = false
    return
  }

  if (!user.uid) {
    error.value = 'No logged-in student found. Please log in again.'
    loading.value = false
    return
  }

  loading.value = true
  error.value = ''

  try {
    const subjectDoc = await getDoc(doc(db, 'subjects', subjectId))

    if (!subjectDoc.exists()) {
      error.value = 'Subject was not found.'
      return
    }

    subject.value = {
      id: subjectDoc.id,
      ...subjectDoc.data(),
    }

    const enrollmentCheckQuery = query(
      collection(db, 'enrollments'),
      where('studentId', '==', user.uid),
      where('subjectId', '==', subjectId)
    )

    const enrollmentCheckSnapshot = await getDocs(enrollmentCheckQuery)

    if (enrollmentCheckSnapshot.empty) {
      error.value = 'You are not enrolled in this subject.'
      return
    }

    const modulesQuery = query(
      collection(db, 'modules'),
      where('subjectId', '==', subjectId)
    )

    const modulesSnapshot = await getDocs(modulesQuery)

    modules.value = modulesSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))

    const activitiesQuery = query(
      collection(db, 'activities'),
      where('subjectId', '==', subjectId)
    )

    const activitiesSnapshot = await getDocs(activitiesQuery)

    activities.value = activitiesSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))

    const submissionsQuery = query(
      collection(db, 'submissions'),
      where('studentId', '==', user.uid),
      where('subjectId', '==', subjectId)
    )

    const submissionsSnapshot = await getDocs(submissionsQuery)

    submissions.value = submissionsSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))

    const classmatesQuery = query(
      collection(db, 'enrollments'),
      where('subjectId', '==', subjectId)
    )

    const classmatesSnapshot = await getDocs(classmatesQuery)

    classmates.value = classmatesSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    }))
  } catch (err) {
    console.error('Subject details loading error:', err)
    error.value = 'Unable to load subject details.'
  } finally {
    loading.value = false
  }
}

function hasSubmitted(activityId) {
  return submittedActivityIds.value.includes(activityId)
}

function getInitials(name) {
  if (!name) return 'U'

  return name
    .split(' ')
    .filter(Boolean)
    .map((word) => word.charAt(0))
    .join('')
    .toUpperCase()
    .slice(0, 2)
}

function formatDate(value) {
  if (!value) return 'No date'

  if (typeof value === 'string') return value

  if (value?.toDate) {
    return value.toDate().toLocaleDateString()
  }

  if (value?.seconds) {
    return new Date(value.seconds * 1000).toLocaleDateString()
  }

  return 'No date'
}

onMounted(fetchSubjectDetails)
</script>

<style scoped>
.animate-fade-in {
  animation: fadeIn 0.25s ease-out forwards;
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
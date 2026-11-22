<template>
  <div class="space-y-6 animate-fade-in">
    <!-- Loading -->
    <SkeletonLoader v-if="loading" variant="details" card />

    <!-- Error -->
    <div
      v-else-if="error"
      class="rounded-[28px] border border-[#DADCE0] bg-white p-6 text-sm font-semibold text-[#D93025]"
    >
      {{ error }}
    </div>

    <template v-else>
      <router-link
        to="/student/subjects"
        class="inline-flex items-center gap-2 text-sm font-medium text-[#667085] transition hover:text-[#800000]"
      >
        <ArrowLeftIcon class="h-4 w-4" />
        Back to Subjects
      </router-link>

      <!-- Class Banner -->
      <section
        class="relative min-h-[320px] overflow-hidden rounded-2xl border border-[#E7E9EE] bg-white p-6 text-[#202124] md:p-8"
      >
        <img :src="subjectBanner" alt="" class="absolute inset-0 h-full w-full rounded-2xl object-cover object-center" />

        <div class="relative z-10 flex min-h-[272px] max-w-full flex-col justify-center sm:max-w-[58%]">
          <p class="text-sm font-medium text-[#5C0000]">
            {{ subject.code || 'Subject' }}
          </p>

          <h1 class="mt-2 text-3xl font-medium tracking-tight text-[#202124] md:text-4xl">
            {{ subject.title || 'Untitled Subject' }}
          </h1>

          <p class="mt-2 max-w-3xl text-sm text-[#5F6368] md:text-base">
            {{ subject.program || 'Program not specified' }}
            <span v-if="subject.section"> • {{ subject.section }}</span>
            <span v-if="subject.instructorName"> • {{ subject.instructorName }}</span>
          </p>

        </div>
      </section>

      <!-- Tabs -->
      <div class="sticky top-24 z-10 rounded-full border border-[#DADCE0] bg-white/90 p-1 shadow-sm backdrop-blur">
        <div class="flex gap-1 overflow-x-auto">
          <button
            v-for="tab in tabs"
            :key="tab.key"
            @click="currentTab = tab.key"
            :class="
              currentTab === tab.key
                ? 'bg-[#800000] text-white shadow-sm'
                : 'text-[#5F6368] hover:bg-[#FDF0F0] hover:text-[#800000]'
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
          <div class="rounded-[24px] border border-[#DADCE0] bg-gradient-to-br from-white to-[#FDF0F0] p-5 shadow-sm">
            <h2 class="text-sm font-black text-[#202124]">Upcoming Activities</h2>

            <div v-if="pendingActivities.length === 0" class="mt-4 text-sm text-[#5F6368]">
              No pending activities for this subject.
            </div>

            <div v-else class="mt-4 space-y-3">
              <div
                v-for="activity in pendingActivities.slice(0, 3)"
                :key="activity.id"
                class="rounded-2xl border border-[#DADCE0] bg-white p-4"
              >
                <p class="text-sm font-bold text-[#202124]">{{ activity.title }}</p>
                <p class="mt-1 text-xs text-[#5F6368]">
                  Due: {{ formatDate(activity.dueDate) }}
                </p>
              </div>
            </div>
          </div>
        </aside>

        <main class="space-y-4 lg:col-span-8 xl:col-span-9">
          <div class="rounded-[24px] border border-[#DADCE0] bg-white p-5 shadow-sm">
            <div class="flex items-center gap-3">
              <div class="flex h-10 w-10 items-center justify-center rounded-full bg-[#800000] text-xs font-bold text-white">
                {{ instructorInitials }}
              </div>

              <div>
                <p class="text-sm font-black text-[#202124]">
                  {{ subject.instructorName || 'Instructor' }}
                </p>
                <p class="text-xs text-[#5F6368]">
                  Welcome to this class. Check the Classwork tab for modules and activities.
                </p>
              </div>
            </div>
          </div>

          <div
            v-if="modules.length === 0 && activities.length === 0"
            class="rounded-[24px] border border-dashed border-[#DADCE0] bg-white p-10 text-center shadow-sm"
          >
            <p class="text-sm font-bold text-[#202124]">No class updates yet.</p>
            <p class="mt-1 text-xs text-[#5F6368]">
              Modules and activities posted by the instructor will appear here.
            </p>
          </div>

          <div
            v-for="item in streamItems"
            :key="item.key"
            class="rounded-[24px] border border-[#DADCE0] bg-white p-5 shadow-sm transition hover:border-[#FDF0F0]"
          >
            <div class="flex items-start gap-3">
              <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#FDF0F0] text-[#800000] ring-1 ring-[#DADCE0]">
                <component :is="item.icon" class="h-5 w-5" />
              </div>

              <div class="min-w-0 flex-1">
                <p class="text-sm font-black text-[#202124]">
                  {{ item.title }}
                </p>
                <p class="mt-1 text-xs font-medium text-[#5F6368]">
                  {{ item.subtitle }}
                </p>
                <p v-if="item.description" class="mt-3 text-sm leading-relaxed text-[#202124]">
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
        <div class="rounded-[28px] border border-[#DADCE0] bg-white shadow-sm">
          <div class="border-b border-[#DADCE0] px-6 py-5">
            <h2 class="text-lg font-black text-[#800000]">Modules</h2>
            <p class="mt-1 text-xs text-[#5F6368]">Learning materials uploaded by your instructor.</p>
          </div>

          <div v-if="modules.length === 0" class="p-8 text-center text-sm text-[#5F6368]">
            No modules uploaded yet.
          </div>

          <div v-else class="divide-y divide-[#DADCE0]/70">
            <a
              v-for="module in modules"
              :key="module.id"
              :href="module.resourceLink || module.fileUrl || '#'"
              :target="module.resourceLink || module.fileUrl ? '_blank' : '_self'"
              class="flex items-center justify-between gap-4 p-5 transition hover:bg-[#F8F9FA]"
            >
              <div class="flex min-w-0 items-center gap-4">
                <div class="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-[#FDF0F0] text-[#800000] ring-1 ring-[#DADCE0]">
                  <FileTextIcon class="h-5 w-5" />
                </div>

                <div class="min-w-0">
                  <p class="truncate text-sm font-black text-[#202124]">
                    {{ module.title || 'Untitled Module' }}
                  </p>
                  <p class="mt-1 text-xs text-[#5F6368]">
                    {{ module.type || 'Learning Material' }}
                    <span v-if="module.createdAt"> • {{ formatDate(module.createdAt) }}</span>
                  </p>
                </div>
              </div>

              <ExternalLinkIcon class="h-4 w-4 shrink-0 text-[#5F6368]" />
            </a>
          </div>
        </div>

        <!-- Activities -->
        <div class="rounded-[28px] border border-[#DADCE0] bg-white shadow-sm">
          <div class="border-b border-[#DADCE0] px-6 py-5">
            <h2 class="text-lg font-black text-[#800000]">Activities</h2>
            <p class="mt-1 text-xs text-[#5F6368]">Assignments and quizzes for this subject.</p>
          </div>

          <div v-if="activities.length === 0" class="p-8 text-center text-sm text-[#5F6368]">
            No activities posted yet.
          </div>

          <div v-else class="divide-y divide-[#DADCE0]/70">
            <router-link
              v-for="activity in activities"
              :key="activity.id"
              to="/student/activities"
              class="flex items-center justify-between gap-4 p-5 transition hover:bg-[#F8F9FA]"
            >
              <div class="flex min-w-0 items-center gap-4">
                <div class="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-[#FDF0F0] text-[#800000] ring-1 ring-[#DADCE0]">
                  <ClipboardListIcon class="h-5 w-5" />
                </div>

                <div class="min-w-0">
                  <p class="truncate text-sm font-black text-[#202124]">
                    {{ activity.title || 'Untitled Activity' }}
                  </p>
                  <p class="mt-1 text-xs text-[#5F6368]">
                    {{ activity.type || 'activity' }}
                    <span v-if="activity.points"> • {{ activity.points }} pts</span>
                    <span> • Due: {{ formatDate(activity.dueDate) }}</span>
                  </p>
                </div>
              </div>

              <span
                :class="hasSubmitted(activity.id) ? 'border-[#DADCE0] bg-white text-[#188038]' : 'border-[#DADCE0] bg-white text-[#D93025]'"
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
        <div class="rounded-[28px] border border-[#DADCE0] bg-white p-6 shadow-sm">
          <h2 class="border-b border-[#DADCE0] pb-3 text-xl font-black text-[#800000]">
            Instructor
          </h2>

          <div class="mt-5 flex items-center gap-3">
            <div class="flex h-11 w-11 items-center justify-center rounded-full bg-[#800000] text-sm font-bold text-white">
              {{ instructorInitials }}
            </div>
            <div>
              <p class="text-sm font-black text-[#202124]">
                {{ subject.instructorName || 'Not assigned' }}
              </p>
              <p class="text-xs text-[#5F6368]">Subject instructor</p>
            </div>
          </div>
        </div>

        <div class="rounded-[28px] border border-[#DADCE0] bg-white p-6 shadow-sm">
          <div class="flex items-center justify-between border-b border-[#DADCE0] pb-3">
            <h2 class="text-xl font-black text-[#800000]">Classmates</h2>
            <span class="text-xs font-bold text-[#5F6368]">{{ classmates.length }} students</span>
          </div>

          <div v-if="classmates.length === 0" class="p-8 text-center text-sm text-[#5F6368]">
            No classmates found.
          </div>

          <div v-else class="divide-y divide-[#DADCE0]/70">
            <div
              v-for="student in classmates"
              :key="student.id"
              class="flex items-center gap-3 py-4"
            >
              <div class="flex h-9 w-9 items-center justify-center rounded-full bg-[#FDF0F0] text-xs font-bold text-[#800000] ring-1 ring-[#DADCE0]">
                {{ getInitials(student.studentName || student.name) }}
              </div>
              <div>
                <p class="text-sm font-bold text-[#202124]">
                  {{ student.studentName || student.name || 'Student' }}
                </p>
                <p class="text-xs text-[#5F6368]">
                  {{ student.studentEmail || student.email || '' }}
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- Grades -->
      <section v-if="currentTab === 'grades'" class="mx-auto max-w-4xl">
        <div class="overflow-hidden rounded-[28px] border border-[#DADCE0] bg-white shadow-sm">
          <div class="flex items-center justify-between border-b border-[#DADCE0] bg-[#F8F9FA] px-6 py-4">
            <div>
              <h2 class="text-lg font-black text-[#800000]">Grades and Feedback</h2>
              <p class="mt-1 text-xs text-[#5F6368]">Your submissions for this subject.</p>
            </div>

            <span class="rounded-full border border-[#DADCE0] bg-[#FDF0F0] px-3 py-1 text-xs font-bold text-[#800000]">
              Average: {{ averageGrade }}%
            </span>
          </div>

          <div v-if="submissions.length === 0" class="p-10 text-center text-sm text-[#5F6368]">
            No submissions or grades yet.
          </div>

          <div v-else class="divide-y divide-[#DADCE0]/70">
            <div
              v-for="submission in submissions"
              :key="submission.id"
              class="p-5 transition hover:bg-[#F8F9FA]"
            >
              <div class="flex items-start justify-between gap-4">
                <div>
                  <p class="text-sm font-black text-[#202124]">
                    {{ submission.activityTitle || 'Activity' }}
                  </p>
                  <p class="mt-1 text-xs text-[#5F6368]">
                    Submitted: {{ formatDate(submission.submittedAt) }}
                  </p>
                  <p v-if="submission.feedback" class="mt-3 text-sm text-[#202124]">
                    Feedback: {{ submission.feedback }}
                  </p>
                </div>

                <div class="text-right">
                  <p class="text-base font-black text-[#800000]">
                    {{ submission.grade !== null && submission.grade !== undefined ? submission.grade : '—' }}
                  </p>
                  <span
                    :class="submission.status === 'graded' ? 'text-[#188038] bg-white border-[#DADCE0]' : 'text-[#D93025] bg-white border-[#DADCE0]'"
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
import SkeletonLoader from '@/components/common/SkeletonLoader.vue'
import subjectBanner from '@/assets/banner.png'
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

    if (subjectDoc.data().archived === true) {
      error.value = 'This subject is no longer active.'
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

    if (!enrollmentCheckSnapshot.docs.some((document) => document.data().archived !== true)) {
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
    })).filter((module) => module.archived !== true)

    const activitiesQuery = query(
      collection(db, 'activities'),
      where('subjectId', '==', subjectId)
    )

    const activitiesSnapshot = await getDocs(activitiesQuery)

    activities.value = activitiesSnapshot.docs.map((document) => ({
      id: document.id,
      ...document.data(),
    })).filter((activity) => activity.archived !== true)

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

    classmates.value = classmatesSnapshot.docs.filter((document) => document.data().archived !== true).map((document) => ({
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

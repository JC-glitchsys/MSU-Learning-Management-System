<template>
  <div class="mx-auto max-w-[1500px] space-y-6 animate-fade-in">
    <header class="flex flex-col gap-3 border-b border-[#E7E9EE] pb-5 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 class="mt-1 text-2xl font-semibold tracking-tight text-[#202124]">System dashboard</h1>
        <p class="mt-1 text-sm text-[#737983]">A live overview of your learning management system.</p>
      </div>
      <p class="text-sm font-medium text-[#5F6368]">{{ todayLabel }}</p>
    </header>

    <section class="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4" aria-label="System summary">
      <article v-for="stat in stats" :key="stat.label" class="dashboard-stat-card flex flex-col rounded-2xl border border-[#E7E9EE] p-5 transition-colors hover:border-[#D8B7B7]">
        <div class="flex items-start justify-between gap-3">
          <p class="text-sm font-medium text-[#737983]">{{ stat.label }}</p>
          <span class="inline-flex shrink-0 items-center gap-1 rounded-md border border-[#E7E9EE] bg-white px-2 py-1 text-xs font-medium" :class="stat.trend.tone">
            <component :is="stat.trend.icon" class="h-3.5 w-3.5" />
            {{ stat.trend.badge }}
          </span>
        </div>
        <p class="mt-3 text-3xl font-semibold tabular-nums tracking-tight text-[#800000]">{{ loading ? '—' : stat.value.toLocaleString() }}</p>
        <div class="mt-5 border-t border-[#ECEEF1] pt-3 text-sm">
          <p class="flex items-center gap-2 font-medium text-[#30343B]">
            {{ stat.trend.headline }}
            <component :is="stat.trend.icon" class="h-4 w-4" :class="stat.trend.tone" />
          </p>
          <p class="mt-1 text-xs text-[#737983]">{{ stat.trend.detail }}</p>
        </div>
      </article>
    </section>

    <section class="grid grid-cols-1 gap-6 xl:grid-cols-12">
      <article class="overflow-hidden rounded-xl border border-[#E7E9EE] bg-white xl:col-span-8">
        <div class="flex flex-col gap-3 border-b border-[#ECEEF1] px-5 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <div>
            <h2 class="text-base font-semibold text-[#202124]">Enrollment activity</h2>
            <p class="mt-1 text-xs text-[#737983]">New student enrollments by month</p>
          </div>
          <label class="flex items-center gap-2 text-xs font-medium text-[#5F6368]">
            <span class="sr-only">Chart range</span>
            <select v-model.number="chartMonths" class="rounded-lg border border-[#DADCE0] bg-white px-3 py-2 text-xs text-[#202124]">
              <option :value="6">Last 6 months</option>
              <option :value="12">Last 12 months</option>
            </select>
          </label>
        </div>
        <div v-if="loading" class="p-6"><SkeletonLoader variant="details" /></div>
        <div v-else class="px-4 pb-5 pt-6 sm:px-6">
          <div class="mb-3 flex items-center gap-2 text-xs text-[#737983]">
            <span class="h-2.5 w-2.5 rounded-full bg-[#800000]"></span>
            Enrollments
          </div>
          <div class="w-full overflow-hidden">
            <svg viewBox="0 0 720 250" class="h-auto w-full" role="img" aria-label="Monthly student enrollment activity chart">
              <g v-for="tick in chartTicks" :key="tick.value">
                <line x1="48" :y1="tick.y" x2="704" :y2="tick.y" stroke="#ECEEF1" stroke-width="1" />
                <text x="38" :y="tick.y + 4" text-anchor="end" fill="#8A8F98" font-size="11">{{ tick.value }}</text>
              </g>
              <polyline :points="chartPoints" fill="none" stroke="#800000" stroke-linecap="round" stroke-linejoin="round" stroke-width="3" />
              <circle v-for="point in chartData" :key="point.key" :cx="point.x" :cy="point.y" r="4" fill="#FFFFFF" stroke="#800000" stroke-width="2.5">
                <title>{{ point.label }}: {{ point.count }} enrollments</title>
              </circle>
              <text v-for="point in chartData" :key="`${point.key}-label`" :x="point.x" y="238" text-anchor="middle" fill="#737983" font-size="11">{{ point.shortLabel }}</text>
            </svg>
          </div>
          <p v-if="!enrollments.length" class="mt-2 text-center text-xs text-[#8A8F98]">Enrollment activity will appear here as records are added.</p>
        </div>
      </article>

      <article class="rounded-xl border border-[#E7E9EE] bg-white xl:col-span-4">
        <div class="border-b border-[#ECEEF1] px-5 py-4 sm:px-6">
          <h2 class="text-base font-semibold text-[#202124]">Quick access</h2>
          <p class="mt-1 text-xs text-[#737983]">Common administration tasks</p>
        </div>
        <nav class="space-y-2 p-4 sm:p-5" aria-label="Admin quick access">
          <router-link v-for="link in quickLinks" :key="link.to" :to="link.to" class="group flex items-center gap-3 rounded-lg border border-transparent p-3 transition hover:border-[#E7E9EE] hover:bg-[#FAFAFB]">
            <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[#FDF0F0] text-[#800000]">
              <component :is="link.icon" class="h-4 w-4" />
            </span>
            <span class="min-w-0 flex-1">
              <span class="block truncate text-sm font-medium text-[#202124]">{{ link.label }}</span>
              <span class="mt-0.5 block truncate text-xs text-[#8A8F98]">{{ link.description }}</span>
            </span>
            <ArrowRight class="h-4 w-4 shrink-0 text-[#8A8F98] transition group-hover:translate-x-0.5 group-hover:text-[#800000]" />
          </router-link>
        </nav>
      </article>
    </section>

    <section class="overflow-hidden rounded-xl border border-[#E7E9EE] bg-white">
      <div class="flex items-center justify-between gap-4 border-b border-[#ECEEF1] px-5 py-4 sm:px-6">
        <div>
          <h2 class="text-base font-semibold text-[#202124]">Recent enrollments</h2>
          <p class="mt-1 text-xs text-[#737983]">Latest student records across the system</p>
        </div>
        <router-link to="/admin/enrollment" class="shrink-0 text-xs font-semibold text-[#800000] hover:underline">View all</router-link>
      </div>

      <SkeletonLoader v-if="loading" variant="table" class="p-5" />
      <div v-else-if="recentEnrollments.length === 0" class="px-6 py-12 text-center">
        <ClipboardList class="mx-auto h-8 w-8 text-[#B8BDC5]" />
        <p class="mt-3 text-sm font-medium text-[#5F6368]">No enrollment records yet</p>
        <p class="mt-1 text-xs text-[#8A8F98]">New enrollments will show here.</p>
      </div>
      <div v-else class="overflow-x-auto">
        <table class="w-full min-w-[620px] text-left">
          <thead class="bg-[#FAFAFB] text-[11px] font-semibold uppercase tracking-wide text-[#737983]">
            <tr>
              <th class="px-5 py-3 sm:px-6">Student</th>
              <th class="px-5 py-3">Subject</th>
              <th class="px-5 py-3">Status</th>
              <th class="px-5 py-3 text-right sm:px-6">Date added</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="record in recentEnrollments" :key="record.id" class="border-t border-[#F0F1F3] transition hover:bg-[#FAFAFB]">
              <td class="px-5 py-3.5 sm:px-6">
                <p class="text-sm font-medium text-[#202124]">{{ record.student }}</p>
                <p class="mt-0.5 text-xs text-[#8A8F98]">{{ record.email || 'No email provided' }}</p>
              </td>
              <td class="px-5 py-3.5 text-sm text-[#5F6368]">{{ record.subject }}</td>
              <td class="px-5 py-3.5"><span class="rounded-full bg-[#EDF7F0] px-2.5 py-1 text-[11px] font-medium capitalize text-[#287D45]">{{ record.status }}</span></td>
              <td class="px-5 py-3.5 text-right text-xs tabular-nums text-[#737983] sm:px-6">{{ record.date }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<script setup>
import SkeletonLoader from '@/components/common/SkeletonLoader.vue'
import { computed, onMounted, ref } from 'vue'
import { collection, getDocs } from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import {
  ArrowDown, ArrowRight, ArrowUp, BookOpen, ClipboardList, GraduationCap, Layers3, Minus, Users,
} from 'lucide-vue-next'

const loading = ref(true)
const chartMonths = ref(6)
const students = ref([])
const instructors = ref([])
const programs = ref([])
const subjects = ref([])
const enrollments = ref([])

const todayLabel = new Intl.DateTimeFormat(undefined, { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' }).format(new Date())

function trendFor(items) {
  const now = new Date()
  const currentMonth = items.filter((item) => {
    const date = toDate(item.createdAt)
    return date && date.getFullYear() === now.getFullYear() && date.getMonth() === now.getMonth()
  }).length
  const previousDate = new Date(now.getFullYear(), now.getMonth() - 1, 1)
  const previousMonth = items.filter((item) => {
    const date = toDate(item.createdAt)
    return date && date.getFullYear() === previousDate.getFullYear() && date.getMonth() === previousDate.getMonth()
  }).length

  if (currentMonth === 0 && previousMonth === 0) {
    return { badge: '—', headline: 'No recent change', detail: 'No new records this month', icon: Minus, tone: 'text-[#737983]' }
  }
  if (previousMonth === 0) {
    return { badge: 'New', headline: `${currentMonth} added this month`, detail: 'No records were added last month', icon: ArrowUp, tone: 'text-[#188038]' }
  }

  const change = Math.round(((currentMonth - previousMonth) / previousMonth) * 100)
  const up = change >= 0
  return {
    badge: `${up ? '+' : ''}${change}%`,
    headline: up ? 'Trending up this month' : 'Down this month',
    detail: `${currentMonth} this month · ${previousMonth} last month`,
    icon: up ? ArrowUp : ArrowDown,
    tone: up ? 'text-[#188038]' : 'text-[#B3261E]',
  }
}

const stats = computed(() => [
  { label: 'Total Students', value: students.value.length, trend: trendFor(students.value), icon: Users },
  { label: 'Instructors', value: instructors.value.length, trend: trendFor(instructors.value), icon: GraduationCap },
  { label: 'Academic Programs', value: programs.value.length, trend: trendFor(programs.value), icon: Layers3 },
  { label: 'Subjects', value: subjects.value.length, trend: trendFor(subjects.value), icon: BookOpen },
])

const recentEnrollments = computed(() => [...enrollments.value]
  .sort((a, b) => b.createdAtMs - a.createdAtMs)
  .slice(0, 6))

const chartData = computed(() => {
  const now = new Date()
  const buckets = Array.from({ length: chartMonths.value }, (_, index) => {
    const date = new Date(now.getFullYear(), now.getMonth() - chartMonths.value + index + 1, 1)
    return {
      key: `${date.getFullYear()}-${date.getMonth()}`,
      label: new Intl.DateTimeFormat(undefined, { month: 'long', year: 'numeric' }).format(date),
      shortLabel: new Intl.DateTimeFormat(undefined, { month: 'short' }).format(date),
      count: 0,
    }
  })

  for (const enrollment of enrollments.value) {
    if (!enrollment.createdAtMs) continue
    const date = new Date(enrollment.createdAtMs)
    const bucket = buckets.find((item) => item.key === `${date.getFullYear()}-${date.getMonth()}`)
    if (bucket) bucket.count += 1
  }

  const max = Math.max(1, ...buckets.map((item) => item.count))
  const step = buckets.length > 1 ? 656 / (buckets.length - 1) : 0
  return buckets.map((item, index) => ({
    ...item,
    x: 48 + step * index,
    y: 205 - (item.count / max) * 165,
  }))
})

const chartPoints = computed(() => chartData.value.map((point) => `${point.x},${point.y}`).join(' '))
const chartTicks = computed(() => {
  const max = Math.max(1, ...chartData.value.map((item) => item.count))
  return [0, 1, 2, 3].map((index) => {
    const value = Math.ceil(max * (3 - index) / 3)
    return { value: index === 3 ? 0 : value, y: 40 + index * 55 }
  })
})

const quickLinks = [
  { to: '/admin/students', label: 'Manage students', description: 'Review student accounts', icon: Users },
  { to: '/admin/instructors', label: 'Manage instructors', description: 'Update faculty records', icon: GraduationCap },
  { to: '/admin/programs', label: 'Manage programs', description: 'Edit academic programs', icon: Layers3 },
  { to: '/admin/subjects', label: 'Manage subjects', description: 'Maintain the curriculum', icon: BookOpen },
]

function toTimestamp(value) {
  if (value?.toDate) return value.toDate().getTime()
  if (typeof value?.seconds === 'number') return value.seconds * 1000
  if (value instanceof Date) return value.getTime()
  return 0
}

function toDate(value) {
  const timestamp = toTimestamp(value)
  return timestamp ? new Date(timestamp) : null
}

function formatDate(timestamp) {
  if (!timestamp) return '—'
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric' }).format(timestamp)
}

async function fetchDashboardData() {
  loading.value = true
  const results = await Promise.allSettled([
    getDocs(collection(db, 'users')),
    getDocs(collection(db, 'programs')),
    getDocs(collection(db, 'subjects')),
    getDocs(collection(db, 'enrollments')),
  ])

  const [usersResult, programsResult, subjectsResult, enrollmentsResult] = results
  if (usersResult.status === 'fulfilled') {
    const users = usersResult.value.docs.map((item) => ({ id: item.id, ...item.data() }))
    students.value = users.filter((item) => item.role === 'student')
    instructors.value = users.filter((item) => item.role === 'instructor')
  } else console.error('Dashboard user metrics could not be loaded:', usersResult.reason)

  if (programsResult.status === 'fulfilled') programs.value = programsResult.value.docs.map((item) => ({ id: item.id, ...item.data() }))
  else console.error('Dashboard program metrics could not be loaded:', programsResult.reason)

  if (subjectsResult.status === 'fulfilled') subjects.value = subjectsResult.value.docs.map((item) => ({ id: item.id, ...item.data() }))
  else console.error('Dashboard subject metrics could not be loaded:', subjectsResult.reason)

  if (enrollmentsResult.status === 'fulfilled') {
    enrollments.value = enrollmentsResult.value.docs
      .map((item) => {
        const data = item.data()
        const createdAtMs = toTimestamp(data.createdAt)
        return {
          id: item.id,
          student: data.studentName || 'Unknown student',
          email: data.studentEmail || '',
          subject: [data.subjectCode, data.subjectTitle].filter(Boolean).join(' · ') || 'Subject not specified',
          status: data.status || 'active',
          createdAtMs,
          date: formatDate(createdAtMs),
          archived: data.archived === true,
        }
      })
      .filter((item) => !item.archived)
  } else console.error('Dashboard enrollment activity could not be loaded:', enrollmentsResult.reason)

  loading.value = false
}

onMounted(fetchDashboardData)
</script>

<style scoped>
.dashboard-stat-card {
  background: linear-gradient(180deg, #FFFFFF 25%, #F0F0F0 100%);
  box-shadow: 0 1px 3px rgb(16 24 40 / 10%);
}
.animate-fade-in { animation: fadeIn 0.2s ease-out forwards; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
</style>

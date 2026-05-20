<template>
  <div class="space-y-8 animate-fade-in">
    <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-msu-border pb-5">
      <div>
        <h2 class="text-2xl md:text-3xl font-black text-msu-maroon tracking-tight">System Command Workspace</h2>
        <p class="text-sm text-[#6B7280] font-medium mt-1">Global audit monitors, enrollment controls, and real-time data logs control board.</p>
      </div>
      <div class="inline-flex px-4 py-2 rounded-full bg-white border border-msu-border text-xs font-bold text-msu-maroon tracking-wide shadow-sm items-center gap-1.5">
        <ShieldCheckIcon class="w-3.5 h-3.5 stroke-[2.5]" />
        <span>Root Administrator View</span>
      </div>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">
      <StatCard title="Total Enrolled Students" :value="totalStudents" description="Active database records" :icon="UsersIcon" iconBg="#FFFFFF" class="border border-msu-border shadow-sm rounded-[24px]" />
      <StatCard title="Total Instructors" :value="totalInstructors" description="Faculty profiles" :icon="GraduationCapIcon" iconBg="#FFFFFF" class="border border-msu-border shadow-sm rounded-[24px]" />
      <StatCard title="Total Degree Programs" :value="totalCourses" description="Offered courses" :icon="FolderIcon" iconBg="#FFFFFF" class="border border-msu-border shadow-sm rounded-[24px]" />
      <StatCard title="Total Active Subjects" :value="totalSubjects" description="Curriculum items" :icon="BookOpenIcon" iconBg="#FFFFFF" class="border border-msu-border shadow-sm rounded-[24px]" />
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
      <div class="lg:col-span-8">
        <CardPanel title="Recent Stream Enrolment Logs">
          <div v-if="loading" class="p-12 text-center">
            <span class="w-6 h-6 border-2 border-msu-maroon border-t-transparent rounded-full animate-spin inline-block"></span>
            <p class="text-xs text-gray-500 font-bold mt-2">Reading registration feeds...</p>
          </div>

          <div v-else-if="enrollments.length === 0" class="p-12 text-center text-[#6B7280]">
            <p class="text-2xl">📋</p>
            <p class="text-xs font-bold mt-2">Zero active cross-link records found inside Firestore enrollments.</p>
          </div>

          <div v-else class="overflow-x-auto -mx-6 px-6">
            <table class="w-full text-sm min-w-[500px]">
              <thead>
                <tr class="text-left text-xs text-[#6B7280] font-bold uppercase tracking-wider border-b border-msu-border">
                  <th class="pb-4 font-bold">Student Identity</th>
                  <th class="pb-4 font-bold">Target Stream Collection</th>
                  <th class="pb-4 font-bold">Registry State</th>
                  <th class="pb-4 font-bold text-right">Date Applied</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-msu-border/60">
                <tr v-for="e in enrollments" :key="e.id" class="hover:bg-msu-page-bg/40 transition group">
                  <td class="py-4">
                    <p class="font-bold text-[#1F2937] group-hover:text-msu-maroon transition-colors">{{ e.student }}</p>
                    <p class="text-[10px] text-gray-400 font-mono">{{ e.email }}</p>
                  </td>
                  <td class="py-4 text-[#6B7280] font-medium text-xs">{{ e.subject }}</td>
                  <td class="py-4">
                    <span class="text-[10px] px-2.5 py-0.5 rounded-full font-bold border uppercase tracking-wide text-green-700 bg-green-50 border-green-200">
                      {{ e.status }}
                    </span>
                  </td>
                  <td class="py-4 text-right text-[#6B7280] font-mono text-xs">{{ e.date }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </CardPanel>
      </div>

      <div class="lg:col-span-4">
        <CardPanel title="Database Control Panels">
          <div class="space-y-2.5">
            <router-link v-for="link in quickLinks" :key="link.to" :to="link.to"
              class="group flex items-center justify-between p-3.5 rounded-2xl bg-white border border-msu-border hover:border-msu-maroon shadow-sm hover:shadow transition-all duration-150">
              <div class="flex items-center gap-3 min-w-0">
                <div class="w-8 h-8 rounded-xl bg-white flex items-center justify-center border border-msu-border text-msu-maroon shadow-sm group-hover:scale-105 transition-transform shrink-0">
                  <component :is="link.icon" class="w-4 h-4 stroke-[2]" />
                </div>
                <span class="text-xs font-bold text-[#1F2937] group-hover:text-msu-maroon transition-colors truncate">{{ link.label }}</span>
              </div>
              <ArrowRightIcon class="w-3.5 h-3.5 text-[#6B7280] group-hover:translate-x-0.5 transition-transform shrink-0" />
            </router-link>
          </div>
        </CardPanel>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { collection, getDocs, query, where } from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import StatCard from '@/components/common/StatCard.vue'
import CardPanel from '@/components/common/CardPanel.vue'
import { 
  UsersIcon, GraduationCapIcon, BookOpenIcon, ClipboardListIcon, 
  ShieldCheckIcon, ArrowRightIcon, FolderIcon, FileTextIcon, BarChart3Icon 
} from 'lucide-vue-next'

// Real-time Metrics Values
const totalStudents = ref(0)
const totalInstructors = ref(0)
const totalCourses = ref(0)
const totalSubjects = ref(0)

const enrollments = ref([])
const loading = ref(true)

const fetchDashboardMetrics = async () => {
  loading.value = true
  try {
    // 1. Bilangin ang students where role == 'student'
    const studentSnap = await getDocs(query(collection(db, 'users'), where('role', '==', 'student')))
    totalStudents.value = studentSnap.size

    // 2. Bilangin ang instructors where role == 'instructor'
    const instructorSnap = await getDocs(query(collection(db, 'users'), where('role', '==', 'instructor')))
    totalInstructors.value = instructorSnap.size

    // 3. Bilangin ang lahat ng degree programs
    const courseSnap = await getDocs(collection(db, 'courses'))
    totalCourses.value = courseSnap.size

    // 4. Bilangin ang lahat ng active subjects
    const subjectSnap = await getDocs(collection(db, 'subjects'))
    totalSubjects.value = subjectSnap.size

    // 5. Humila ng totoong recent records mula sa 'enrollments' collection
    const enrollSnap = await getDocs(collection(db, 'enrollments'))
    enrollments.value = enrollSnap.docs.map(doc => {
      const data = doc.data()
      // Safe Date Conversion handler loop
      let formattedDate = 'Just now'
      if (data.createdAt) {
        formattedDate = new Date(data.createdAt.seconds * 1000).toLocaleDateString(undefined, {
          month: 'short',
          day: 'numeric',
          year: 'numeric'
        })
      }
      
      return {
        id: doc.id,
        student: data.studentName || 'Unknown Student',
        email: data.studentEmail || '',
        subject: `${data.subjectCode || ''} - ${data.subjectTitle || ''}`,
        status: 'active',
        date: formattedDate
      }
    }).slice(0, 5) // Kunin lang ang top 5 pinakabagong logs para hindi humaba ang layout

  } catch (err) {
    console.error("Firestore loading error inside dashboard analytics layer:", err)
  } finally {
    loading.value = false
  }
}

const quickLinks = [
  { to: '/admin/students', label: 'Manage Student Directory', icon: UsersIcon },
  { to: '/admin/instructors', label: 'Faculty Roster Master', icon: GraduationCapIcon },
  { to: '/admin/courses', label: 'Academic Programs Index', icon: FolderIcon },
  { to: '/admin/subjects', label: 'Curriculum Subjects Base', icon: BookOpenIcon },
  { to: '/admin/enrollment', label: 'Enrolment Cross-Manager', icon: FileTextIcon },
  { to: '/admin/reports', label: 'Generate System Audits', icon: BarChart3Icon },
]

onMounted(fetchDashboardMetrics)
</script>

<style scoped>
.animate-fade-in { animation: fadeIn 0.2s ease-out forwards; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
</style>
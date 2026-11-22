<template>
  <div class="space-y-8 animate-fade-in">
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
      <div class="lg:col-span-8">
        <CardPanel title="Recent Stream Enrolment Logs">
          <SkeletonLoader v-if="loading" variant="table" />

          <div v-else-if="enrollments.length === 0" class="p-12 text-center text-[#5F6368]">
            <p class="text-2xl">📋</p>
            <p class="text-xs font-bold mt-2">Zero active cross-link records found inside Firestore enrollments.</p>
          </div>

          <div v-else class="overflow-x-auto -mx-6 px-6">
            <table class="w-full text-sm min-w-[500px]">
              <thead>
                <tr class="text-left text-xs text-[#5F6368] font-bold uppercase tracking-wider border-b border-msu-border">
                  <th class="pb-4 font-bold">Student Identity</th>
                  <th class="pb-4 font-bold">Target Stream Collection</th>
                  <th class="pb-4 font-bold">Registry State</th>
                  <th class="pb-4 font-bold text-right">Date Applied</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-msu-border/60">
                <tr v-for="e in enrollments" :key="e.id" class="hover:bg-msu-page-bg/40 transition group">
                  <td class="py-4">
                    <p class="font-bold text-[#202124] group-hover:text-msu-maroon transition-colors">{{ e.student }}</p>
                    <p class="text-[10px] text-[#5F6368] font-mono">{{ e.email }}</p>
                  </td>
                  <td class="py-4 text-[#5F6368] font-medium text-xs">{{ e.subject }}</td>
                  <td class="py-4">
                    <span class="text-[10px] px-2.5 py-0.5 rounded-full font-bold border uppercase tracking-wide text-[#188038] bg-white border-[#DADCE0]">
                      {{ e.status }}
                    </span>
                  </td>
                  <td class="py-4 text-right text-[#5F6368] font-mono text-xs">{{ e.date }}</td>
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
                <span class="text-xs font-bold text-[#202124] group-hover:text-msu-maroon transition-colors truncate">{{ link.label }}</span>
              </div>
              <ArrowRightIcon class="w-3.5 h-3.5 text-[#5F6368] group-hover:translate-x-0.5 transition-transform shrink-0" />
            </router-link>
          </div>
        </CardPanel>
      </div>
    </div>
  </div>
</template>

<script setup>
import SkeletonLoader from '@/components/common/SkeletonLoader.vue'
import { ref, onMounted } from 'vue'
import { collection, getDocs } from 'firebase/firestore'
import { db } from '../../firebase/config.js'
import CardPanel from '@/components/common/CardPanel.vue'
import { 
  UsersIcon, GraduationCapIcon, BookOpenIcon,
  ArrowRightIcon, FolderIcon, FileTextIcon, BarChart3Icon
} from 'lucide-vue-next'

const enrollments = ref([])
const loading = ref(true)

const fetchRecentEnrollments = async () => {
  loading.value = true
  try {
    // Load the recent enrollment records displayed below.
    const enrollSnap = await getDocs(collection(db, 'enrollments'))
    enrollments.value = enrollSnap.docs.filter((doc) => doc.data().archived !== true).map(doc => {
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

onMounted(fetchRecentEnrollments)
</script>

<style scoped>
.animate-fade-in { animation: fadeIn 0.2s ease-out forwards; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
</style>

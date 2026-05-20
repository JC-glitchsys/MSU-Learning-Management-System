<template>
  <div class="space-y-8 animate-fade-in">
    <div>
      <h2 class="text-3xl md:text-4xl font-bold text-[#800000] tracking-tight">My Enrolled Classes</h2>
      <p class="text-[#6B7280] mt-2 font-medium text-sm">Select an active class card to open the classroom workspace stream.</p>
    </div>

    <div v-if="loading" class="p-12 text-center bg-white rounded-[28px] border border-[#E7DCC3] shadow-sm">
      <span class="w-8 h-8 border-4 border-[#800000]/30 border-t-[#800000] rounded-full animate-spin inline-block"></span>
      <p class="text-xs font-bold text-[#800000] mt-3">Connecting to enrollment directory...</p>
    </div>

    <div v-else-if="error" class="p-12 text-center bg-white rounded-[28px] border border-[#E7DCC3] shadow-sm text-red-600 font-bold">
      {{ error }}
    </div>

    <div v-else-if="enrolledSubjects.length === 0" class="p-12 text-center bg-white rounded-[28px] border border-[#E7DCC3] shadow-sm text-[#6B7280]">
      <p class="text-4xl">📚</p>
      <p class="text-sm font-bold mt-2">You are not enrolled in any subjects yet.</p>
      <p class="text-xs mt-1">Please coordinate with your system registrar or program adviser.</p>
    </div>

    <div v-else class="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-3">
      <div 
        v-for="sub in enrolledSubjects" 
        :key="sub.id"
        @click="openSubjectStream(sub.subjectId)"
        class="overflow-hidden rounded-[24px] border border-[#E7DCC3] bg-white shadow-sm transition-all duration-200 hover:-translate-y-1 hover:shadow-md cursor-pointer group flex flex-col justify-between"
      >
        <div class="h-28 bg-gradient-to-r from-[#800000] via-[#9A1B1B] to-[#D4AF37] p-5 text-white relative shrink-0">
          <div class="absolute inset-0 bg-white/5 skew-y-12 transform origin-top-right transition-transform group-hover:scale-105 duration-300"></div>
          <div class="relative z-10">
            <h3 class="text-base font-bold tracking-tight text-white group-hover:underline truncate">{{ sub.subjectTitle }}</h3>
            <p class="text-xs text-white/80 font-mono tracking-wider mt-0.5">{{ sub.subjectCode }}</p>
          </div>
        </div>

        <div class="p-5 space-y-4 bg-white flex-1 flex flex-col justify-between">
          <div class="space-y-1">
            <p class="text-xs font-bold text-[#1F2937] truncate">👨‍🏫 {{ sub.instructorName || 'Unassigned Faculty' }}</p>
            <p class="text-[10px] text-[#6B7280] font-medium">Mindanao State University Integrated Stream</p>
          </div>

          <div class="pt-3 border-t border-[#E7DCC3]/50 flex items-center justify-between text-[11px] font-bold text-[#800000]">
            <span class="uppercase tracking-wide">Enter Classroom</span>
            <span>→</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { collection, query, where, getDocs } from 'firebase/firestore'
import { db } from '../../firebase/config.js'

const router = useRouter()
const enrolledSubjects = ref([])
const loading = ref(true)
const error = ref('')

const user = JSON.parse(localStorage.getItem('user') || '{}')

const fetchStudentEnrollments = async () => {
  if (!user.uid) {
    error.value = 'Identity mapping missing. Please log in again.'
    loading.value = false
    return
  }
  loading.value = true
  try {
    const q = query(collection(db, 'enrollments'), where('studentId', '==', user.uid))
    const snap = await getDocs(q)
    enrolledSubjects.value = snap.docs.map(d => ({ id: d.id, ...d.data() }))
  } catch (err) {
    console.error(err)
    error.value = 'Failed to fetch your academic enrollment collection.'
  } finally {
    loading.value = false
  }
}

const openSubjectStream = (subjectId) => {
  router.push(`/student/subjects/${subjectId}`)
}

onMounted(fetchStudentEnrollments)
</script>

<style scoped>
.animate-fade-in { animation: fadeIn 0.2s ease-out forwards; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
</style>
<template>
  <div class="space-y-8 animate-fade-in">
    <div>
      <h2 class="text-3xl md:text-4xl font-bold text-[#800000] tracking-tight">My Enrolled Classes</h2>
      <p class="text-[#5F6368] mt-2 font-medium text-sm">Select an active class card to open the classroom workspace stream.</p>
    </div>

    <SkeletonLoader v-if="loading" variant="cards" card />

    <div v-else-if="error" class="p-12 text-center bg-white rounded-[28px] border border-[#DADCE0] shadow-sm text-[#D93025] font-bold">
      {{ error }}
    </div>

    <div v-else-if="enrolledSubjects.length === 0" class="p-12 text-center bg-white rounded-[28px] border border-[#DADCE0] shadow-sm text-[#5F6368]">
      <p class="text-4xl">📚</p>
      <p class="text-sm font-bold mt-2">You are not enrolled in any subjects yet.</p>
      <p class="text-xs mt-1">Please coordinate with your system registrar or program adviser.</p>
    </div>

    <div v-else class="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-3">
      <div 
        v-for="sub in enrolledSubjects" 
        :key="sub.id"
        @click="openSubjectStream(sub.subjectId)"
        class="overflow-hidden rounded-[24px] border border-[#DADCE0] bg-white shadow-sm transition-all duration-200 hover:-translate-y-1 hover:shadow-md cursor-pointer group flex flex-col justify-between"
      >
        <div class="subject-card-banner relative h-40 shrink-0 overflow-hidden bg-white p-5 text-[#800000]">
          <img :src="subjectBanner" alt="" class="absolute inset-0 h-full w-full object-contain object-right" />
          <div class="relative z-10 max-w-[58%]">
            <p class="truncate text-sm font-medium text-[#5C0000]">{{ sub.subjectCode }}</p>
            <h3 class="mt-1 truncate text-xl font-medium tracking-tight text-[#800000]">{{ sub.subjectTitle }}</h3>
          </div>
        </div>

        <div class="p-5 space-y-4 bg-white flex-1 flex flex-col justify-between">
          <div class="space-y-1">
            <p class="truncate text-xs font-medium text-[#202124]">{{ sub.instructorName || 'Unassigned Faculty' }}</p>
            <p v-if="sub.section" class="text-xs text-[#5F6368]">{{ sub.section }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import SkeletonLoader from '@/components/common/SkeletonLoader.vue'
import subjectBanner from '@/assets/banner.png'
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
    const subjectSnap = await getDocs(collection(db, 'subjects'))
    const activeSubjectIds = new Set(subjectSnap.docs.filter((subject) => subject.data().archived !== true).map((subject) => subject.id))
    enrolledSubjects.value = snap.docs.map(d => ({ id: d.id, ...d.data() })).filter((item) => item.archived !== true && activeSubjectIds.has(item.subjectId))
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

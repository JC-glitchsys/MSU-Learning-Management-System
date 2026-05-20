<template>
  <div class="space-y-8 animate-fade-in">
    <div>
      <h2 class="text-3xl md:text-4xl font-bold text-[#800000] tracking-tight">Academic Performance Records</h2>
      <p class="text-[#6B7280] mt-1 font-medium text-sm">Review final graded markers, status checkpoints, and advisor critique logs.</p>
    </div>

    <div v-if="loading" class="p-12 text-center bg-white rounded-[28px] border border-[#E7DCC3] shadow-sm"><span class="w-6 h-6 border-4 border-[#800000]/30 border-t-[#800000] rounded-full animate-spin inline-block"></span></div>
    
    <div v-else class="space-y-8">
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div class="bg-white border border-[#E7DCC3] rounded-2xl p-4 shadow-sm text-center">
          <p class="text-[10px] text-gray-400 font-bold uppercase tracking-wider">Total Handed In</p>
          <p class="text-2xl font-black text-[#800000] mt-0.5">{{ submissions.length }}</p>
        </div>
        <div class="bg-white border border-[#E7DCC3] rounded-2xl p-4 shadow-sm text-center">
          <p class="text-[10px] text-gray-400 font-bold uppercase tracking-wider">Graded Items</p>
          <p class="text-2xl font-black text-green-700 mt-0.5">{{ gradedItems.length }}</p>
        </div>
        <div class="bg-white border border-[#E7DCC3] rounded-2xl p-4 shadow-sm text-center">
          <p class="text-[10px] text-gray-400 font-bold uppercase tracking-wider">Pending Review</p>
          <p class="text-2xl font-black text-amber-700 mt-0.5">{{ pendingItems.length }}</p>
        </div>
        <div class="bg-white border border-[#E7DCC3] rounded-2xl p-4 shadow-sm text-center">
          <p class="text-[10px] text-gray-400 font-bold uppercase tracking-wider">Semester Average Score</p>
          <p class="text-2xl font-black text-[#800000] mt-0.5">{{ runningAverage }}%</p>
        </div>
      </div>

      <div class="space-y-4 max-w-4xl">
        <h3 class="text-sm font-bold text-[#1F2937] uppercase tracking-wider border-b border-[#E7DCC3] pb-2">Evaluated Portfolio Items Sheets</h3>
        
        <div v-if="submissions.length === 0" class="p-8 text-center text-xs text-gray-400 bg-white border border-[#E7DCC3] rounded-2xl">No history submission nodes tracked in this account configuration.</div>
        
        <div v-for="g in submissions" :key="g.id" class="bg-white rounded-2xl border border-[#E7DCC3] p-5 shadow-sm space-y-3">
          <div class="flex items-center justify-between gap-4 border-b border-[#E7DCC3]/40 pb-2.5">
            <div>
              <span class="inline-block text-[10px] font-bold bg-[#FAFAF7] border border-[#E7DCC3] text-[#800000] px-2.5 py-0.5 rounded-full mb-1">{{ g.subjectCode }}</span>
              <h4 class="text-sm font-bold text-[#1F2937] tracking-tight">{{ g.subjectTitle }}</h4>
            </div>
            <div class="text-right">
              <span v-if="g.status === 'graded'" class="text-base font-black text-green-700 block">{{ g.grade }} Pts</span>
              <span v-else class="text-xs font-bold text-amber-700 block uppercase tracking-wide">Pending Review</span>
            </div>
          </div>
          
          <div v-if="g.feedback" class="bg-[#FAFAF7] border-l-4 border-[#D4AF37] p-3 rounded-r-xl text-xs text-[#1F2937]">
            <p class="font-bold text-[#800000] mb-0.5">💬 Instructor Critique Feedback:</p>
            <p class="italic font-medium leading-relaxed">"{{ g.feedback }}"</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { collection, query, where, getDocs } from 'firebase/firestore'
import { db } from '../../firebase/config.js'

const user = JSON.parse(localStorage.getItem('user') || '{}')
const loading = ref(true)
const submissions = ref([])

const fetchGradeBookIndex = async () => {
  loading.value = true
  try {
    const q = query(collection(db, 'submissions'), where('studentId', '==', user.uid))
    const snap = await getDocs(q)
    submissions.value = snap.docs.map(d => ({ id: d.id, ...d.data() }))
  } catch (err) {
    console.error(err)
  } finally {
    loading.value = false
  }
}

const gradedItems = computed(() => submissions.value.filter(s => s.status === 'graded'))
const pendingItems = computed(() => submissions.value.filter(s => s.status !== 'graded'))

const runningAverage = computed(() => {
  if (gradedItems.value.length === 0) return '0'
  const total = gradedItems.value.reduce((acc, curr) => acc + (curr.grade || 0), 0)
  return Math.round(total / gradedItems.value.length)
})

onMounted(fetchGradeBookIndex)
</script>

<style scoped>
.animate-fade-in { animation: fadeIn 0.2s ease-out forwards; }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
</style>
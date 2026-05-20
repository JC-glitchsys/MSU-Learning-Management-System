<template>
  <div class="space-y-8 animate-fade-in">
    <div>
      <h2 class="text-3xl md:text-4xl font-bold text-[#800000] tracking-tight">My Handled Subjects</h2>
      <p class="text-[#6B7280] mt-2 font-medium text-sm">Access your assigned classroom streams and operations panels.</p>
    </div>

    <div v-if="loading" class="p-12 text-center bg-white rounded-[28px] border border-[#E7DCC3] shadow-sm">
      <span class="w-8 h-8 border-4 border-[#800000]/30 border-t-[#800000] rounded-full animate-spin inline-block"></span>
    </div>

    <div v-else-if="error" class="p-12 text-center bg-white rounded-[28px] border border-[#E7DCC3] shadow-sm text-red-600 font-bold">
      {{ error }}
    </div>

    <div v-else-if="assignedSubjects.length === 0" class="p-12 text-center bg-white rounded-[28px] border border-[#E7DCC3] shadow-sm text-[#6B7280]">
      <p class="text-4xl">📚</p>
      <p class="text-sm font-bold mt-2">No assigned subjects found.</p>
      <p class="text-xs mt-0.5">Please contact the System Admin to allocate your curriculum sheets.</p>
    </div>

    <div v-else class="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-3">
      <div v-for="subj in assignedSubjects" :key="subj.id" class="overflow-hidden rounded-[24px] border border-[#E7DCC3] bg-white shadow-sm transition hover:-translate-y-1 hover:shadow-md flex flex-col justify-between group">
        
        <div class="h-28 bg-gradient-to-r from-[#800000] via-[#9A1B1B] to-[#D4AF37] p-5 text-white relative">
          <div class="absolute inset-0 bg-white/5 skew-y-12 transform origin-top-right"></div>
          <div class="relative z-10">
            <h3 class="text-base font-bold tracking-tight text-white group-hover:underline truncate">{{ subj.title }}</h3>
            <p class="text-xs text-white/80 font-mono tracking-wider mt-0.5">{{ subj.code }} • Section {{ subj.section }}</p>
          </div>
        </div>

        <div class="p-5 space-y-4 bg-white flex-1 flex flex-col justify-between">
          <div class="text-xs font-bold text-[#6B7280] uppercase tracking-wider">
            Tracking Program: {{ subj.program || 'General Program' }}
          </div>

          <div class="pt-4 border-t border-[#E7DCC3]/50 grid grid-cols-3 gap-2 text-center">
            <router-link to="/instructor/upload-module" class="px-2 py-2 rounded-xl bg-[#FAFAF7] border border-[#E7DCC3] text-[10px] font-bold text-[#800000] hover:bg-[#FFF8E1] transition">📂 Modules</router-link>
            <router-link to="/instructor/create-activity" class="px-2 py-2 rounded-xl bg-[#FAFAF7] border border-[#E7DCC3] text-[10px] font-bold text-[#800000] hover:bg-[#FFF8E1] transition">✏️ Activity</router-link>
            <router-link to="/instructor/submissions" class="px-2 py-2 rounded-xl bg-[#FAFAF7] border border-[#E7DCC3] text-[10px] font-bold text-[#800000] hover:bg-[#FFF8E1] transition">📥 Review</router-link>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { collection, query, where, getDocs } from 'firebase/firestore'
import { db } from '../../firebase/config.js'

const assignedSubjects = ref([])
const loading = ref(true)
const error = ref('')

const user = JSON.parse(localStorage.getItem('user') || '{}')

const fetchAssignedStreams = async () => {
  if (!user.uid) {
    error.value = 'Identity validation verification mapping failed.'
    loading.value = false
    return
  }
  try {
    const q = query(collection(db, 'subjects'), where('instructorId', '==', user.uid))
    const snap = await getDocs(q)
    assignedSubjects.value = snap.docs.map(d => ({ id: d.id, ...d.data() }))
  } catch (err) {
    error.value = 'Security isolation failure fetching teacher tracks.'
  } finally {
    loading.value = false
  }
}

onMounted(fetchAssignedStreams)
</script>
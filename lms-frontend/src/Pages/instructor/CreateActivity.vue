<template>
  <div class="space-y-8 animate-fade-in max-w-4xl mx-auto">
    <div>
      <h2 class="text-3xl md:text-4xl font-bold text-[#800000] tracking-tight">Deploy Classwork Tasks</h2>
      <p class="text-[#6B7280] mt-1 font-medium text-sm">Issue structured evaluation tasks and quizzes to student timelines.</p>
    </div>

    <div class="bg-white rounded-[28px] border border-[#E7DCC3] shadow-sm p-6">
      <form @submit.prevent="saveActivity" class="space-y-4">
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div class="space-y-1.5">
            <label class="text-[11px] font-bold text-[#1F2937] uppercase tracking-wider">Select Subject</label>
            <select v-model="formData.subjectId" required class="w-full rounded-[12px] border border-[#E7DCC3] px-4 py-2.5 text-xs bg-white outline-none">
              <option value="">Select target section...</option>
              <option v-for="s in subjects" :key="s.id" :value="s.id">{{ s.code }} - {{ s.title }}</option>
            </select>
          </div>
          <div class="space-y-1.5">
            <label class="text-[11px] font-bold text-[#1F2937] uppercase tracking-wider">Task Category Type</label>
            <select v-model="formData.type" required class="w-full rounded-[12px] border border-[#E7DCC3] px-4 py-2.5 text-xs bg-white outline-none">
              <option value="assignment">Assignment Task</option>
              <option value="quiz">Quiz / Exam</option>
            </select>
          </div>
          <div class="space-y-1.5">
            <label class="text-[11px] font-bold text-[#1F2937] uppercase tracking-wider">Max Points Scale</label>
            <input v-model="formData.points" required type="number" min="0" class="w-full rounded-[12px] border border-[#E7DCC3] px-4 py-2.5 text-xs outline-none" />
          </div>
          <div class="space-y-1.5 sm:col-span-2">
            <label class="text-[11px] font-bold text-[#1F2937] uppercase tracking-wider">Assessment Title</label>
            <input v-model="formData.title" required type="text" placeholder="e.g. Activity 2: Database Schema Map" class="w-full rounded-[12px] border border-[#E7DCC3] px-4 py-2.5 text-xs outline-none" />
          </div>
          <div class="space-y-1.5">
            <label class="text-[11px] font-bold text-[#1F2937] uppercase tracking-wider">Target Due Deadline</label>
            <input v-model="formData.dueDate" required type="date" class="w-full rounded-[12px] border border-[#E7DCC3] px-4 py-2.5 text-xs cursor-pointer outline-none" />
          </div>
          <div class="col-span-1 sm:col-span-3 space-y-1.5">
            <label class="text-[11px] font-bold text-[#1F2937] uppercase tracking-wider">Instructions Guidelines & Rubrics Statement</label>
            <textarea v-model="formData.instructions" rows="3" class="w-full rounded-[12px] border border-[#E7DCC3] px-4 py-2.5 text-xs resize-none outline-none"></textarea>
          </div>
        </div>
        <div class="pt-4 flex justify-end border-t border-[#E7DCC3]/40">
          <button type="submit" :disabled="saving" class="rounded-full bg-[#800000] text-white font-bold text-xs px-6 py-2.5 hover:bg-[#5A0000] transition">
            {{ saving ? 'Deploying...' : 'Deploy Classwork Task' }}
          </button>
        </div>
      </form>
    </div>

    <div class="space-y-3">
      <h3 class="text-sm font-bold text-[#1F2937] uppercase tracking-wider">Active Published Requirements Timeline</h3>
      
      <div v-if="loading" class="p-6 text-center bg-white rounded-2xl border border-[#E7DCC3]">
        <span class="w-6 h-6 border-2 border-[#800000] border-t-transparent rounded-full animate-spin inline-block"></span>
      </div>
      <div v-else-if="activities.length === 0" class="p-8 text-center bg-white rounded-2xl border border-[#E7DCC3] text-xs text-[#6B7280]">
        No active assessments published.
      </div>

      <div v-else v-for="act in activities" :key="act.id" class="bg-white rounded-2xl border border-[#E7DCC3] p-4 shadow-sm flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div class="flex items-center gap-3 min-w-0">
          <div class="w-9 h-9 rounded-xl bg-[#FAFAF7] border border-[#E7DCC3] flex items-center justify-center text-base shrink-0">📝</div>
          <div class="min-w-0">
            <h4 class="text-xs font-bold text-[#1F2937] truncate">{{ act.title }}</h4>
            <p class="text-[10px] font-bold text-[#800000] mt-0.5">{{ act.subjectCode }} • <span class="text-gray-500 font-mono font-medium">Max: {{ act.points }} Pts</span></p>
          </div>
        </div>
        <div class="flex items-center gap-3 shrink-0 justify-between sm:justify-end">
          <span class="text-[10px] font-bold text-red-600 bg-red-50 border border-red-100 px-3 py-1 rounded-full">⚠️ Due {{ act.dueDate }}</span>
          <button @click="deleteActivity(act.id)" class="text-xs text-red-600 hover:underline font-bold">Purge</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { collection, query, where, getDocs, addDoc, doc, deleteDoc, serverTimestamp } from 'firebase/firestore'
import { db } from '../../firebase/config.js'

const user = JSON.parse(localStorage.getItem('user') || '{}')
const subjects = ref([])
const activities = ref([])
const loading = ref(true)
const saving = ref(false)
const formData = ref({ subjectId: '', title: '', instructions: '', type: 'assignment', dueDate: '', points: 100, rubric: '' })

const fetchRequirements = async () => {
  loading.value = true
  try {
    const subSnap = await getDocs(query(collection(db, 'subjects'), where('instructorId', '==', user.uid)))
    subjects.value = subSnap.docs.map(d => ({ id: d.id, ...d.data() }))

    const actSnap = await getDocs(query(collection(db, 'activities'), where('createdBy', '==', user.uid)))
    activities.value = actSnap.docs.map(d => ({ id: d.id, ...d.data() }))
  } catch (err) {
    console.error(err)
  } finally {
    // Naitama na rito ang structural finally tracker block!
    loading.value = false
  }
}

const saveActivity = async () => {
  saving.value = true
  try {
    const match = subjects.value.find(s => s.id === formData.value.subjectId)
    const payload = {
      ...formData.value,
      subjectCode: match ? match.code : 'TBA',
      subjectTitle: match ? match.title : 'TBA',
      createdBy: user.uid,
      createdByName: user.name,
      createdAt: serverTimestamp()
    }
    await addDoc(collection(db, 'activities'), payload)
    formData.value = { subjectId: '', title: '', instructions: '', type: 'assignment', dueDate: '', points: 100, rubric: '' }
    await fetchRequirements()
  } catch (err) {
    alert('Security deployment layer error.')
  } finally {
    saving.value = false
  }
}

const deleteActivity = async (id) => {
  if (!confirm('Purge this assignment item node?')) return
  try {
    await deleteDoc(doc(db, 'activities', id))
    await fetchRequirements()
  } catch (err) {
    alert('Operation error.')
  }
}

onMounted(fetchRequirements)
</script>
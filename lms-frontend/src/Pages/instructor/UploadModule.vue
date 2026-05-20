<template>
  <div class="space-y-8 animate-fade-in max-w-4xl mx-auto">
    <div>
      <h2 class="text-3xl md:text-4xl font-bold text-[#800000] tracking-tight">Course Modules Workbench</h2>
      <p class="text-[#6B7280] mt-1 font-medium text-sm">Upload and manage reading assets assigned across your streams.</p>
    </div>

    <div class="bg-white rounded-[28px] border border-[#E7DCC3] shadow-sm p-6">
      <form @submit.prevent="saveModule" class="space-y-4">
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div class="space-y-1.5">
            <label class="text-[11px] font-bold text-[#1F2937] uppercase tracking-wider">Target Subject Group</label>
            <select v-model="formData.subjectId" required class="w-full rounded-[12px] border border-[#E7DCC3] px-4 py-2.5 text-xs outline-none bg-white">
              <option value="">Select target stream...</option>
              <option v-for="sub in subjects" :key="sub.id" :value="sub.id">{{ sub.code }} - {{ sub.title }}</option>
            </select>
          </div>
          <div class="space-y-1.5 sm:col-span-2">
            <label class="text-[11px] font-bold text-[#1F2937] uppercase tracking-wider">Module Title</label>
            <input v-model="formData.title" required type="text" placeholder="e.g. Chapter 1: Architecture Core" class="w-full rounded-[12px] border border-[#E7DCC3] px-4 py-2.5 text-xs outline-none" />
          </div>
          <div class="space-y-1.5">
            <label class="text-[11px] font-bold text-[#1F2937] uppercase tracking-wider">Asset Type</label>
            <select v-model="formData.type" required class="w-full rounded-[12px] border border-[#E7DCC3] px-4 py-2.5 text-xs outline-none bg-white">
              <option value="Lecture Notes">Lecture Notes</option>
              <option value="Video">Video Resource</option>
              <option value="Reading Resource">Reading Material</option>
            </select>
          </div>
          <div class="space-y-1.5 sm:col-span-2">
            <label class="text-[11px] font-bold text-[#1F2937] uppercase tracking-wider">Resource External Asset Link URL</label>
            <input v-model="formData.resourceLink" required type="url" placeholder="https://drive.google.com/..." class="w-full rounded-[12px] border border-[#E7DCC3] px-4 py-2.5 text-xs outline-none" />
          </div>
          <div class="col-span-1 sm:col-span-3 space-y-1.5">
            <label class="text-[11px] font-bold text-[#1F2937] uppercase tracking-wider">Description Brief</label>
            <textarea v-model="formData.description" rows="2" class="w-full rounded-[12px] border border-[#E7DCC3] px-4 py-2.5 text-xs outline-none resize-none"></textarea>
          </div>
        </div>
        <div class="pt-4 flex justify-end border-t border-[#E7DCC3]/40">
          <button type="submit" :disabled="saving" class="rounded-full bg-[#800000] text-white font-bold text-xs px-6 py-2.5 hover:bg-[#5A0000]">
            {{ saving ? 'Publishing Link...' : (isEditing ? 'Update Module Data' : 'Publish Class Module') }}
          </button>
        </div>
      </form>
    </div>

    <div class="space-y-3">
      <h3 class="text-sm font-bold text-[#1F2937] uppercase tracking-wider">My Active Uploaded Modules Feed</h3>
      
      <div v-if="loading" class="p-6 text-center bg-white rounded-2xl border border-[#E7DCC3]"><span class="w-4 h-4 border-2 border-[#800000] border-t-transparent rounded-full animate-spin inline-block"></span></div>
      <div v-else-if="modules.length === 0" class="p-8 text-center bg-white rounded-2xl border border-[#E7DCC3] text-xs text-[#6B7280]">No items published yet.</div>
      
      <div v-else v-for="m in modules" :key="m.id" class="bg-white rounded-2xl border border-[#E7DCC3] p-4 shadow-sm flex items-center justify-between gap-4">
        <div class="flex items-center gap-3 min-w-0">
          <div class="w-9 h-9 rounded-xl bg-[#FAFAF7] border border-[#E7DCC3] flex items-center justify-center text-lg shrink-0">📄</div>
          <div class="min-w-0">
            <h4 class="text-xs font-bold text-[#1F2937] truncate">{{ m.title }}</h4>
            <p class="text-[10px] font-bold text-[#800000] mt-0.5">{{ m.subjectCode }} • <span class="text-[#6B7280] font-medium">{{ m.type }}</span></p>
          </div>
        </div>
        <div class="space-x-3 shrink-0">
          <a :href="m.resourceLink" target="_blank" class="text-xs text-[#D4AF37] hover:underline font-bold">Open Asset</a>
          <button @click="deleteModule(m.id)" class="text-xs text-red-600 hover:underline">Purge</button>
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
const modules = ref([])
const loading = ref(true)
const saving = ref(false)
const isEditing = ref(false)
const formData = ref({ subjectId: '', title: '', description: '', type: 'Lecture Notes', resourceLink: '' })

const fetchRequirements = async () => {
  loading.value = true
  try {
    const subSnap = await getDocs(query(collection(db, 'subjects'), where('instructorId', '==', user.uid)))
    subjects.value = subSnap.docs.map(d => ({ id: d.id, ...d.data() }))

    const modSnap = await getDocs(query(collection(db, 'modules'), where('createdBy', '==', user.uid)))
    modules.value = modSnap.docs.map(d => ({ id: d.id, ...d.data() }))
  } catch (err) {
    console.error(err)
  } finally {
    loading.value = false
  }
}

const saveModule = async () => {
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
    await addDoc(collection(db, 'modules'), payload)
    formData.value = { subjectId: '', title: '', description: '', type: 'Lecture Notes', resourceLink: '' }
    await fetchRequirements()
  } catch (err) {
    alert('Error deploying asset document framework.')
  } finally {
    saving.value = false
  }
}

const deleteModule = async (id) => {
  if (!confirm('Purge module node from database?')) return
  try {
    await deleteDoc(doc(db, 'modules', id))
    await fetchRequirements()
  } catch (err) {
    alert('Deletion error.')
  }
}

onMounted(fetchRequirements)
</script>
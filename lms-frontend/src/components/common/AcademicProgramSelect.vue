<template>
  <div class="grid grid-cols-1 gap-4">
    <label class="flex flex-col gap-1.5">
      <span class="text-sm font-medium text-[#4B515B]">College</span>
      <select
        :value="modelValue.college"
        required
        :disabled="loading || colleges.length === 0"
        class="h-11 w-full rounded-lg border border-[#DADCE0] bg-white px-3 text-sm text-[#202124] outline-none focus:border-[#800000] disabled:cursor-not-allowed disabled:bg-[#F8F9FA]"
        @change="selectCollege($event.target.value)"
      >
        <option disabled value="">{{ loading ? 'Loading colleges...' : 'Select college' }}</option>
        <option v-for="college in colleges" :key="college" :value="college">{{ college }}</option>
      </select>
    </label>

    <label class="flex flex-col gap-1.5">
      <span class="text-sm font-medium text-[#4B515B]">Department</span>
      <select
        :value="modelValue.department"
        required
        :disabled="loading || !modelValue.college || departments.length === 0"
        class="h-11 w-full rounded-lg border border-[#DADCE0] bg-white px-3 text-sm text-[#202124] outline-none focus:border-[#800000] disabled:cursor-not-allowed disabled:bg-[#F8F9FA]"
        @change="selectDepartment($event.target.value)"
      >
        <option disabled value="">{{ modelValue.college ? 'Select department' : 'Select a college first' }}</option>
        <option v-for="department in departments" :key="department" :value="department">{{ department }}</option>
      </select>
    </label>

    <label class="flex flex-col gap-1.5">
      <span class="text-sm font-medium text-[#4B515B]">Academic Program</span>
      <select
        :value="modelValue.program"
        required
        :disabled="loading || !modelValue.department || programsForDepartment.length === 0"
        class="h-11 w-full rounded-lg border border-[#DADCE0] bg-white px-3 text-sm text-[#202124] outline-none focus:border-[#800000] disabled:cursor-not-allowed disabled:bg-[#F8F9FA]"
        @change="selectProgram($event.target.value)"
      >
        <option disabled value="">{{ modelValue.department ? 'Select program' : 'Select a department first' }}</option>
        <option v-for="program in programsForDepartment" :key="program.id" :value="program.value">
          {{ program.label }}
        </option>
      </select>
    </label>

    <p v-if="error" class="text-xs text-[#B3261E]" role="alert">{{ error }}</p>
    <p v-else-if="!loading && colleges.length === 0" class="text-xs text-[#5F6368]">
      No academic programs are configured yet. Add them in Manage Programs.
    </p>
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { collection, getDocs } from 'firebase/firestore'
import { db } from '@/firebase/config.js'

const props = defineProps({
  modelValue: {
    type: Object,
    default: () => ({ college: '', department: '', program: '' }),
  },
})
const emit = defineEmits(['update:modelValue'])

const records = ref([])
const loading = ref(true)
const error = ref('')

function collegeOf(record) {
  // Older program records used `department` as the college field.
  return String(record.college || record.department || '').trim()
}

function departmentOf(record) {
  return String(record.department || record.college || '').trim()
}

function uniqueSorted(values) {
  const unique = new Map()
  values.filter(Boolean).forEach((value) => {
    const label = String(value).trim()
    if (label && !unique.has(label.toLocaleLowerCase())) unique.set(label.toLocaleLowerCase(), label)
  })
  return [...unique.values()].sort((a, b) => a.localeCompare(b))
}

const colleges = computed(() => uniqueSorted(records.value.map(collegeOf)))
const departments = computed(() => uniqueSorted(
  records.value
    .filter((record) => collegeOf(record) === props.modelValue.college)
    .map(departmentOf),
))
const programsForDepartment = computed(() => records.value
  .filter((record) => collegeOf(record) === props.modelValue.college
    && departmentOf(record) === props.modelValue.department
    && (record.archived !== true
      || (record.programCode || record.programName) === props.modelValue.program))
  .map((record) => ({
    id: record.id,
    value: record.programCode || record.programName,
    label: record.programCode
      ? `${record.programCode} — ${record.programName || 'Untitled Program'}`
      : record.programName || 'Untitled Program',
  }))
  .filter((program) => program.value))

function update(value) {
  emit('update:modelValue', { ...props.modelValue, ...value })
}

function selectCollege(college) {
  update({ college, department: '', program: '' })
}

function selectDepartment(department) {
  update({ department, program: '' })
}

function selectProgram(program) {
  update({ program })
}

function hydrateExistingProgram() {
  if (loading.value || !props.modelValue.program || props.modelValue.college) return

  const currentProgram = String(props.modelValue.program).trim().toLocaleLowerCase()
  const record = records.value.find((item) => [item.programCode, item.programName]
    .some((value) => String(value || '').trim().toLocaleLowerCase() === currentProgram))

  if (record) {
    update({ college: collegeOf(record), department: departmentOf(record) })
  }
}

watch(() => [props.modelValue.program, props.modelValue.college, records.value.length], hydrateExistingProgram)

onMounted(async () => {
  try {
    const snapshot = await getDocs(collection(db, 'programs'))
    records.value = snapshot.docs.map((document) => ({ id: document.id, ...document.data() }))
  } catch (fetchError) {
    console.error('Load academic programs error:', fetchError)
    error.value = 'Could not load academic programs. Please try again.'
  } finally {
    loading.value = false
    hydrateExistingProgram()
  }
})
</script>

import { doc, serverTimestamp, updateDoc } from 'firebase/firestore'

export function isArchived(record) {
  return record?.archived === true
}

export function filterArchived(records, showArchived = false) {
  return records.filter((record) => isArchived(record) === showArchived)
}

export async function setRecordArchived(db, collectionName, id, archived) {
  await updateDoc(doc(db, collectionName, id), {
    archived,
    archivedAt: archived ? serverTimestamp() : null,
  })
}

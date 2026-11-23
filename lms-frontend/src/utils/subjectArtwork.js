const mathTerms = /\b(?:math|mathematics|algebra|calculus|statistics?|geometry|trigonometry|probability|quantitative)\b/i
const mathCode = /(?:^|[^a-z])(?:mth|stat|calc|geom|alg)(?:[^a-z]|$)/i

const codingTerms = /\b(?:coding|programming|software|computer science|web development|web programming|information technology|computer|algorithms?|data structures?|cybersecurity|networking)\b/i
const codingCode = /(?:^|[^a-z])(?:cs|csc|csit|itec|ite|it|comp|ict|cit)(?:\s|[-_])*\d/i

export function getSubjectArtworkType(subject = {}) {
  const category = [
    subject.category,
    subject.subjectCategory,
    subject.categoryName,
    subject.subjectArea,
    subject.discipline,
  ]
    .filter(Boolean)
    .join(' ')
  const subjectInfo = [
    subject.title,
    subject.subjectTitle,
    subject.code,
    subject.subjectCode,
    subject.description,
    subject.summary,
  ].filter(Boolean).join(' ')
  const program = subject.program || ''

  if (mathTerms.test(category)) return 'calculator'
  if (codingTerms.test(category)) return 'laptop'
  if (mathTerms.test(subjectInfo) || mathCode.test(subjectInfo)) return 'calculator'
  if (codingTerms.test(subjectInfo) || codingCode.test(subjectInfo)) return 'laptop'
  if (mathTerms.test(program)) return 'calculator'
  if (codingTerms.test(program)) return 'laptop'
  return 'notebook'
}

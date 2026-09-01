import { defineLoader } from 'vitepress'

const latestReleaseUrl = 'https://github.com/ForkbombEu/sd-jwt-zk/releases/latest'
const benchmarkUrl = `${latestReleaseUrl}/download/sd-jwt-zk-benchmarks.json`

type Measurement = {
  family: string
  operation: string
  duration_ms: number
  proof_bytes: number
  presentation_proof_bytes: number
  credential_proof_bytes: number
  kb_proof_bytes: number
  status_proof_bytes: number
}

type BenchmarkFile = {
  metadata: {
    version: string
    generated_at: string
    iterations: number
    cpu: string
    system: string
    timing_policy: string
  }
  measurements: Measurement[]
}

export type OperationSummary = {
  name: string
  label: string
  durationMs: number
  durationMinMs: number
  durationMaxMs: number
  proofBytes: number
  proofMinBytes: number
  proofMaxBytes: number
  durationRatio: number
}

export type ArtifactSummary = {
  name: string
  label: string
  bytes: number
  ratio: number
}

export type FamilySummary = {
  name: string
  label: string
  description: string
  operations: OperationSummary[]
  artifacts: ArtifactSummary[]
  proofBytes: number
}

export type BenchmarkData = {
  version: string
  generatedAt: string
  iterations: number
  cpu: string
  system: string
  timingPolicy: string
  releaseUrl: string
  benchmarkUrl: string
  families: FamilySummary[]
}

declare const data: BenchmarkData
export { data }

const familyDetails: Record<string, { label: string; description: string }> = {
  'bearer-exact-key-with-status': {
    label: 'Bearer + revocation',
    description: 'Exact-key bearer presentation with a private revocation check.',
  },
  'holder-bound-exact-key': {
    label: 'Holder-bound',
    description: 'Exact-key credential, key-binding, and revocation proofs.',
  },
  'local-valid-status': {
    label: 'Revocation list',
    description: 'Standalone private VALID membership proof.',
  },
}

// Keep experimental measurements in the release data without presenting them
// as a supported public benchmark family.
const unpublishedFamilyNames = new Set(['local-valid-status'])

const operationLabels: Record<string, string> = {
  prove: 'Prove',
  rerandomize: 'Rerandomize',
  verify: 'Verify',
}

const artifactFields = [
  ['presentation', 'Presentation', 'presentation_proof_bytes'],
  ['credential', 'Credential', 'credential_proof_bytes'],
  ['key-binding', 'Key binding', 'kb_proof_bytes'],
  ['status', 'Revocation', 'status_proof_bytes'],
] as const

const fallback: BenchmarkFile = {
  metadata: {
    version: '1.0.0',
    generated_at: '2026-08-31T21:46:13.645591+00:00',
    iterations: 2,
    cpu: 'AMD EPYC 9V74 80-Core Processor',
    system: 'Linux-6.17.0-1022-azure-x86_64-with-glibc2.39',
    timing_policy: 'Descriptive wall-clock observations; not performance thresholds or release promises.',
  },
  measurements: [
    { family: 'bearer-exact-key-with-status', operation: 'prove', duration_ms: 6478, proof_bytes: 902940, presentation_proof_bytes: 657356, credential_proof_bytes: 0, kb_proof_bytes: 0, status_proof_bytes: 245548 },
    { family: 'bearer-exact-key-with-status', operation: 'prove', duration_ms: 6378, proof_bytes: 902076, presentation_proof_bytes: 657132, credential_proof_bytes: 0, kb_proof_bytes: 0, status_proof_bytes: 244908 },
    { family: 'bearer-exact-key-with-status', operation: 'rerandomize', duration_ms: 4195, proof_bytes: 902940, presentation_proof_bytes: 657356, credential_proof_bytes: 0, kb_proof_bytes: 0, status_proof_bytes: 245548 },
    { family: 'bearer-exact-key-with-status', operation: 'rerandomize', duration_ms: 4190, proof_bytes: 902076, presentation_proof_bytes: 657132, credential_proof_bytes: 0, kb_proof_bytes: 0, status_proof_bytes: 244908 },
    { family: 'bearer-exact-key-with-status', operation: 'verify', duration_ms: 2634, proof_bytes: 902940, presentation_proof_bytes: 657356, credential_proof_bytes: 0, kb_proof_bytes: 0, status_proof_bytes: 245548 },
    { family: 'bearer-exact-key-with-status', operation: 'verify', duration_ms: 2646, proof_bytes: 902076, presentation_proof_bytes: 657132, credential_proof_bytes: 0, kb_proof_bytes: 0, status_proof_bytes: 244908 },
    { family: 'holder-bound-exact-key', operation: 'prove', duration_ms: 8870, proof_bytes: 648516, presentation_proof_bytes: 0, credential_proof_bytes: 257580, kb_proof_bytes: 145484, status_proof_bytes: 245452 },
    { family: 'holder-bound-exact-key', operation: 'prove', duration_ms: 9021, proof_bytes: 647620, presentation_proof_bytes: 0, credential_proof_bytes: 257292, kb_proof_bytes: 145676, status_proof_bytes: 244652 },
    { family: 'holder-bound-exact-key', operation: 'verify', duration_ms: 4008, proof_bytes: 648516, presentation_proof_bytes: 0, credential_proof_bytes: 257580, kb_proof_bytes: 145484, status_proof_bytes: 245452 },
    { family: 'holder-bound-exact-key', operation: 'verify', duration_ms: 4014, proof_bytes: 647620, presentation_proof_bytes: 0, credential_proof_bytes: 257292, kb_proof_bytes: 145676, status_proof_bytes: 244652 },
    { family: 'local-valid-status', operation: 'prove', duration_ms: 974, proof_bytes: 245388, presentation_proof_bytes: 0, credential_proof_bytes: 0, kb_proof_bytes: 0, status_proof_bytes: 245388 },
    { family: 'local-valid-status', operation: 'prove', duration_ms: 974, proof_bytes: 244588, presentation_proof_bytes: 0, credential_proof_bytes: 0, kb_proof_bytes: 0, status_proof_bytes: 244588 },
    { family: 'local-valid-status', operation: 'rerandomize', duration_ms: 973, proof_bytes: 245388, presentation_proof_bytes: 0, credential_proof_bytes: 0, kb_proof_bytes: 0, status_proof_bytes: 245388 },
    { family: 'local-valid-status', operation: 'rerandomize', duration_ms: 972, proof_bytes: 244588, presentation_proof_bytes: 0, credential_proof_bytes: 0, kb_proof_bytes: 0, status_proof_bytes: 244588 },
    { family: 'local-valid-status', operation: 'verify', duration_ms: 588, proof_bytes: 245388, presentation_proof_bytes: 0, credential_proof_bytes: 0, kb_proof_bytes: 0, status_proof_bytes: 245388 },
    { family: 'local-valid-status', operation: 'verify', duration_ms: 587, proof_bytes: 244588, presentation_proof_bytes: 0, credential_proof_bytes: 0, kb_proof_bytes: 0, status_proof_bytes: 244588 },
  ],
}

function median(values: number[]) {
  const sorted = [...values].sort((a, b) => a - b)
  const middle = Math.floor(sorted.length / 2)
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
}

function summarize(raw: BenchmarkFile): BenchmarkData {
  const publishedMeasurements = raw.measurements.filter(
    ({ family }) => !unpublishedFamilyNames.has(family),
  )
  const maxDuration = Math.max(...publishedMeasurements.map(({ duration_ms }) => duration_ms))
  const families = Object.entries(familyDetails)
    .filter(([name]) => !unpublishedFamilyNames.has(name))
    .map(([name, details]) => {
      const measurements = raw.measurements.filter((measurement) => measurement.family === name)
      const operations = [...new Set(measurements.map(({ operation }) => operation))].map((operation) => {
        const samples = measurements.filter((measurement) => measurement.operation === operation)
        const durations = samples.map(({ duration_ms }) => duration_ms)
        const sizes = samples.map(({ proof_bytes }) => proof_bytes)
        const durationMs = median(durations)

        return {
          name: operation,
          label: operationLabels[operation] ?? operation,
          durationMs,
          durationMinMs: Math.min(...durations),
          durationMaxMs: Math.max(...durations),
          proofBytes: median(sizes),
          proofMinBytes: Math.min(...sizes),
          proofMaxBytes: Math.max(...sizes),
          durationRatio: durationMs / maxDuration,
        }
      })
      const representative = measurements[0]
      const proofBytes = median(measurements.map(({ proof_bytes }) => proof_bytes))
      const artifacts = artifactFields
        .map(([artifactName, label, field]) => ({
          name: artifactName,
          label,
          bytes: median(measurements.map((measurement) => measurement[field])),
          ratio: median(measurements.map((measurement) => measurement[field])) / proofBytes,
        }))
        .filter(({ bytes }) => bytes > 0)

      return { name, ...details, operations, artifacts, proofBytes: representative ? proofBytes : 0 }
    })

  return {
    version: raw.metadata.version,
    generatedAt: raw.metadata.generated_at,
    iterations: raw.metadata.iterations,
    cpu: raw.metadata.cpu,
    system: raw.metadata.system,
    timingPolicy: raw.metadata.timing_policy,
    releaseUrl: `https://github.com/ForkbombEu/sd-jwt-zk/releases/tag/v${raw.metadata.version}`,
    benchmarkUrl,
    families,
  }
}

export default defineLoader({
  async load(): Promise<BenchmarkData> {
    try {
      const response = await fetch(benchmarkUrl, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(8_000),
      })
      if (!response.ok) throw new Error(`Benchmark download returned ${response.status}`)
      return summarize(await response.json() as BenchmarkFile)
    } catch {
      return summarize(fallback)
    }
  },
})

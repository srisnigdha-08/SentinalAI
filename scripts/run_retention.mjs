/**
 * scripts/run_retention.mjs
 *
 * Task 8: Data Retention CLI Trigger & Archival Verification Tool
 *
 * Usage:
 *   node scripts/run_retention.mjs --dry-run
 *   node scripts/run_retention.mjs --apply --force
 *   node scripts/run_retention.mjs --restore
 *
 * INVARIANTS:
 * - Disabled by default; dry-run by default.
 * - Never touches auditlogs.
 * - Never touches demo-* sessions or their linked threats.
 * - Archives all records to archived_* collections before deletion.
 */

import mongoose from '../backend/node_modules/mongoose/index.js'
import {
  dryRunRetention,
  applyRetention,
  restoreFromArchive,
  getRetentionConfig,
} from '../backend/services/retentionService.js'

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db'

function parseArgs() {
  const args = process.argv.slice(2)
  const options = {
    dryRun: true,
    force: false,
    restore: false,
    daysThreats: undefined,
    daysSessions: undefined,
    batchSize: undefined,
  }

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    if (arg === '--apply') {
      options.dryRun = false
    } else if (arg === '--dry-run') {
      options.dryRun = true
    } else if (arg === '--force') {
      options.force = true
    } else if (arg === '--restore') {
      options.restore = true
    } else if (arg === '--days-threats' && args[i + 1]) {
      options.daysThreats = parseInt(args[++i], 10)
    } else if (arg === '--days-sessions' && args[i + 1]) {
      options.daysSessions = parseInt(args[++i], 10)
    } else if (arg === '--batch-size' && args[i + 1]) {
      options.batchSize = parseInt(args[++i], 10)
    }
  }

  return options
}

async function run() {
  const options = parseArgs()
  console.log('='.repeat(70))
  console.log(' SENTINEL-AI DATA RETENTION & ARCHIVAL MANAGER')
  console.log('='.repeat(70))
  console.log(`Database URI : ${MONGO_URI.replace(/\/\/[^:]+:[^@]+@/, '//***:***@')}`)
  console.log(`Execution Mode: ${options.restore ? 'RESTORE FROM ARCHIVE' : options.dryRun ? 'DRY-RUN (SIMULATION ONLY)' : 'APPLY (ARCHIVE & PURGE)'}\n`)

  await mongoose.connect(MONGO_URI)

  try {
    if (options.restore) {
      console.log('--- RESTORING FROM ARCHIVE COLLECTIONS ---')
      const restoreResult = await restoreFromArchive()
      console.log(`Restored Threats  : ${restoreResult.restored.threats}`)
      console.log(`Restored Sessions : ${restoreResult.restored.sessions}`)
      console.log(`Restored Alerts   : ${restoreResult.restored.alerts}`)
      console.log('\n✓ Restoration complete.')
      return
    }

    if (options.dryRun) {
      console.log('--- DRY-RUN RETENTION SIMULATION ---')
      const simulation = await dryRunRetention(options)
      console.log(`Policy Status            : ${simulation.enabled ? 'ENABLED' : 'DISABLED (default safe mode)'}`)
      console.log(`Threats Age Cutoff       : ${simulation.policyConfig.daysThreats} days (${simulation.cutoffs.threatsCutoff})`)
      console.log(`Sessions Age Cutoff      : ${simulation.policyConfig.daysSessions} days (${simulation.cutoffs.sessionsCutoff})`)
      console.log(`Batch Size Limit         : ${simulation.policyConfig.batchSize}`)
      console.log('')
      console.log('--- ELIGIBLE RECORDS TO ARCHIVE & PURGE ---')
      console.log(`ThreatLogs Eligible      : ${simulation.counts.threatsEligible}`)
      console.log(`HoneypotSessions Eligible: ${simulation.counts.sessionsEligible}`)
      console.log(`Dependent Alerts Eligible: ${simulation.counts.dependentAlertsEligible}`)
      console.log(`Predictions to Unlink    : ${simulation.counts.predictionsToUnlink}`)
      console.log(`Total Records Impacted   : ${simulation.counts.totalRecordsEligible}`)
      console.log('')
      console.log('--- SAFETY GUARANTEES & PRESERVATION ---')
      console.log(`AuditLogs Touched        : ${simulation.safetyGuarantees.auditLogsTouched} (Strictly Excluded)`)
      console.log(`Demo Sessions Excluded   : ${simulation.safetyGuarantees.demoSessionsExcluded} (Strictly Excluded)`)
      console.log(`Demo Threats Protected   : ${simulation.safetyGuarantees.demoThreatsProtected} (Strictly Excluded)`)
      console.log('')
      console.log('DRY-RUN COMPLETE: Zero documents were modified, archived, or deleted.')
    } else {
      console.log('--- APPLYING RETENTION POLICY ---')
      const result = await applyRetention({
        ...options,
        dryRun: false,
        actor: { id: 'admin-cli', name: 'CLI Administrator', role: 'admin' },
      })

      if (!result.applied) {
        console.warn(`[ABORTED] ${result.reason}`)
        return
      }

      console.log(`Timestamp           : ${result.timestamp}`)
      console.log('--- ARCHIVAL RESULTS ---')
      console.log(`Threats Archived    : ${result.archived.threats} -> archived_threatlogs`)
      console.log(`Sessions Archived   : ${result.archived.sessions} -> archived_honeypotsessions`)
      console.log(`Alerts Archived     : ${result.archived.alerts} -> archived_alerts`)
      console.log('')
      console.log('--- DELETION RESULTS ---')
      console.log(`Threats Deleted     : ${result.deleted.threats}`)
      console.log(`Sessions Deleted    : ${result.deleted.sessions}`)
      console.log(`Alerts Deleted      : ${result.deleted.alerts}`)
      console.log(`Predictions Unlinked: ${result.deleted.predictionsUnlinked}`)
      console.log('')
      console.log('✓ Archival completed before deletion. Rollback available via --restore.')
    }
  } catch (err) {
    console.error('Retention execution error:', err)
    process.exitCode = 1
  } finally {
    await mongoose.disconnect()
    console.log('='.repeat(70))
  }
}

run()

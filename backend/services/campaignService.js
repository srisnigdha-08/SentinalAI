const Campaign = require('../models/Campaign')
const HoneypotSession = require('../models/HoneypotSession')
const logger = require('../utils/logger')
const crypto = require('crypto')

/**
 * Computes Jaccard Similarity between two sessions based on their commands.
 */
const getJaccardSimilarity = (s1, s2) => {
  const cmds1 = (s1.commands || []).map((c) => (c.command || '').trim()).filter(Boolean)
  const cmds2 = (s2.commands || []).map((c) => (c.command || '').trim()).filter(Boolean)

  if (cmds1.length === 0 && cmds2.length === 0) return 1.0
  if (cmds1.length === 0 || cmds2.length === 0) return 0.0

  const set1 = new Set(cmds1)
  const set2 = new Set(cmds2)

  let intersection = 0
  for (const cmd of set1) {
    if (set2.has(cmd)) {
      intersection++
    }
  }

  const union = set1.size + set2.size - intersection
  return intersection / union
}

/**
 * Computes the threat level of a campaign based on its max deception score and AI threat score.
 */
const computeThreatLevel = (maxDeception, maxAiThreat) => {
  if (maxAiThreat >= 0.8 || maxDeception >= 80) return 'CRITICAL'
  if (maxAiThreat >= 0.6 || maxDeception >= 50) return 'HIGH'
  if (maxAiThreat >= 0.3 || maxDeception >= 20) return 'MEDIUM'
  return 'LOW'
}

const SIMILARITY_THRESHOLD = 0.65
const CANDIDATE_LIMIT = 200
const uniqueCommands = (s) => new Set((s.commands || []).map((c) => (c.command || '').trim()).filter(Boolean))

// Clustering rule: exact non-empty hassh, OR Jaccard command similarity >= 0.65 with >= 3 unique commands each.
const sessionsMatch = (a, b) => {
  const hasshMatches = Boolean(a.hassh && b.hassh && a.hassh === b.hassh)
  const commandsMatch =
    uniqueCommands(a).size >= 3 && uniqueCommands(b).size >= 3 && getJaccardSimilarity(a, b) >= SIMILARITY_THRESHOLD
  return hasshMatches || commandsMatch
}

/**
 * Clusters a newly closed session.
 *
 * Only sessions from the last 7 days that could satisfy the rule are loaded: same hassh, or at least one
 * shared command (Jaccard >= 0.65 is impossible without one). Both lookups are indexed, and only the
 * campaigns containing those candidates are read, instead of every campaign and session (M6).
 */
const clusterSession = async (session) => {
  try {
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
    const commands = [...uniqueCommands(session)]
    const criteria = []
    if (session.hassh) criteria.push({ hassh: session.hassh })
    if (commands.length >= 3) criteria.push({ 'commands.command': { $in: commands } })
    if (criteria.length === 0) {
      logger.info(`[Campaign] No matching campaign or standalone session for ${session.sessionId}.`)
      return null
    }

    const candidates = await HoneypotSession.find({
      _id: { $ne: session._id },
      createdAt: { $gte: sevenDaysAgo },
      $or: criteria,
    })
      .sort({ createdAt: -1 })
      .limit(CANDIDATE_LIMIT)
    const matching = candidates.filter((candidate) => sessionsMatch(session, candidate))
    const matchingIds = matching.map((m) => m._id)

    // 1. An active (recent) campaign that already contains a matching session
    const matchedCampaign = matchingIds.length
      ? await Campaign.findOne({ sessions: { $in: matchingIds }, lastSeen: { $gte: sevenDaysAgo } }).sort({
          lastSeen: -1,
        })
      : null

    if (matchedCampaign) {
      // Add session to existing campaign
      matchedCampaign.sessions.push(session._id)

      // Update timestamps
      if (session.startTime && session.startTime < matchedCampaign.firstSeen) {
        matchedCampaign.firstSeen = session.startTime
      }
      const end = session.endTime || new Date()
      if (end > matchedCampaign.lastSeen) {
        matchedCampaign.lastSeen = end
      } else {
        matchedCampaign.lastSeen = new Date()
      }

      // Update source IPs
      if (!matchedCampaign.sourceIPs.includes(session.sourceIP)) {
        matchedCampaign.sourceIPs.push(session.sourceIP)
      }

      // Update max scores
      matchedCampaign.maxDeceptionScore = Math.max(matchedCampaign.maxDeceptionScore, session.deceptionScore || 0)
      matchedCampaign.maxAiThreatScore = Math.max(matchedCampaign.maxAiThreatScore, session.aiThreatScore || 0)

      // Recompute threat level
      matchedCampaign.threatLevel = computeThreatLevel(
        matchedCampaign.maxDeceptionScore,
        matchedCampaign.maxAiThreatScore
      )

      await matchedCampaign.save()
      logger.info(`[Campaign] Added session ${session.sessionId} to campaign ${matchedCampaign.campaignId}`)
      return matchedCampaign
    }

    // 2. Otherwise pair with a matching closed session that is in no campaign yet
    const inCampaigns = matchingIds.length
      ? new Set(
          (await Campaign.find({ sessions: { $in: matchingIds } }, 'sessions')).flatMap((c) =>
            c.sessions.map((s) => s.toString())
          )
        )
      : new Set()
    const matchedStandalone = matching.find((m) => m.status === 'closed' && !inCampaigns.has(m._id.toString())) || null

    if (matchedStandalone) {
      // Create a new campaign
      const campaignId = `CAMP-${crypto.randomBytes(4).toString('hex').toUpperCase()}`

      const firstSeen = new Date(
        Math.min(session.startTime || session.createdAt, matchedStandalone.startTime || matchedStandalone.createdAt)
      )
      const lastSeen = new Date(
        Math.max(session.endTime || session.createdAt, matchedStandalone.endTime || matchedStandalone.createdAt)
      )

      const sourceIPs = Array.from(new Set([session.sourceIP, matchedStandalone.sourceIP]))

      const maxDeceptionScore = Math.max(session.deceptionScore || 0, matchedStandalone.deceptionScore || 0)
      const maxAiThreatScore = Math.max(session.aiThreatScore || 0, matchedStandalone.aiThreatScore || 0)

      const threatLevel = computeThreatLevel(maxDeceptionScore, maxAiThreatScore)

      const newCampaign = await Campaign.create({
        campaignId,
        sessions: [matchedStandalone._id, session._id],
        firstSeen,
        lastSeen,
        sourceIPs,
        maxDeceptionScore,
        maxAiThreatScore,
        threatLevel,
      })

      logger.info(
        `[Campaign] Created new campaign ${campaignId} linking sessions ${session.sessionId} and ${matchedStandalone.sessionId}`
      )
      return newCampaign
    }

    logger.info(`[Campaign] No matching campaign or standalone session for ${session.sessionId}.`)
    return null
  } catch (err) {
    logger.error(`[Campaign] Error clustering session: ${err.message}`)
    return null
  }
}

module.exports = {
  clusterSession,
  getJaccardSimilarity,
  sessionsMatch,
}

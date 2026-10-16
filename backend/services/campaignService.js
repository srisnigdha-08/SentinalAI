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

/**
 * Clusters a newly closed session.
 */
const clusterSession = async (session) => {
  try {
    const SIMILARITY_THRESHOLD = 0.65
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)

    // 1. Search for matching recent campaigns
    const recentCampaigns = await Campaign.find({
      lastSeen: { $gte: sevenDaysAgo },
    }).populate('sessions')

    let matchedCampaign = null

    for (const campaign of recentCampaigns) {
      if (!campaign.sessions || campaign.sessions.length === 0) continue

      // Check if session matches ANY session in this campaign
      let matchesCampaign = false
      for (const memberSession of campaign.sessions) {
        // Condition 1: Exact matching non-empty hassh
        const hasshMatches = session.hassh && memberSession.hassh && session.hassh === memberSession.hassh
        // Condition 2: Jaccard command similarity >= 0.65 (enforces minimum 3 unique commands floor)
        const uniqueCmds1 = new Set((session.commands || []).map((c) => (c.command || '').trim()).filter(Boolean))
        const uniqueCmds2 = new Set((memberSession.commands || []).map((c) => (c.command || '').trim()).filter(Boolean))
        const commandsMatch =
          uniqueCmds1.size >= 3 &&
          uniqueCmds2.size >= 3 &&
          getJaccardSimilarity(session, memberSession) >= SIMILARITY_THRESHOLD

        if (hasshMatches || commandsMatch) {
          matchesCampaign = true
          break
        }
      }

      if (matchesCampaign) {
        matchedCampaign = campaign
        break
      }
    }

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

    // 2. If no campaign matches, look for matching recent standalone sessions
    const allCampaigns = await Campaign.find({}, 'sessions')
    const sessionIdsInCampaigns = allCampaigns.reduce((acc, c) => acc.concat(c.sessions.map((s) => s.toString())), [])

    const standaloneSessions = await HoneypotSession.find({
      _id: { $nin: sessionIdsInCampaigns, $ne: session._id },
      status: 'closed',
      createdAt: { $gte: sevenDaysAgo },
    })

    let matchedStandalone = null
    for (const standalone of standaloneSessions) {
      const hasshMatches = session.hassh && standalone.hassh && session.hassh === standalone.hassh
      // Enforces minimum 3 unique commands floor for similarity branch
      const uniqueCmds1 = new Set((session.commands || []).map((c) => (c.command || '').trim()).filter(Boolean))
      const uniqueCmds2 = new Set((standalone.commands || []).map((c) => (c.command || '').trim()).filter(Boolean))
      const commandsMatch =
        uniqueCmds1.size >= 3 &&
        uniqueCmds2.size >= 3 &&
        getJaccardSimilarity(session, standalone) >= SIMILARITY_THRESHOLD

      if (hasshMatches || commandsMatch) {
        matchedStandalone = standalone
        break
      }
    }

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
}

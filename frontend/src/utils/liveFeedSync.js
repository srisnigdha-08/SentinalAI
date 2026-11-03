// WS-002: which threats from the REST "recent" list the Live Feed should add after a reconnect. Only threats it has
// not shown (by id) and that are newer than the newest it has seen; older ones were already displayed or scrolled off
// and must not reappear at the top. Returned newest first, like the feed.

/** @returns {object[]} threats to add, newest first */
export function feedThreatsToRecover(recent, seenIds, newestSeenAt) {
  if (!Array.isArray(recent)) return []
  return recent
    .filter((t) => {
      const id = t?._id || t?.id
      if (!id || seenIds.has(id)) return false
      const at = Date.parse(t.createdAt)
      if (!Number.isFinite(at)) return false
      return newestSeenAt === null || newestSeenAt === undefined || at >= newestSeenAt // ids already shown were removed above
    })
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
}

/** Adds rows to the feed newest first by `at` (ms); equal times keep the newly added row on top. Bounded to max. */
export function insertByTime(feed, rows, max) {
  return [...rows, ...feed]
    .map((row, i) => ({ row, i }))
    .sort((a, b) => (b.row.at ?? 0) - (a.row.at ?? 0) || a.i - b.i)
    .map(({ row }) => row)
    .slice(0, max)
}

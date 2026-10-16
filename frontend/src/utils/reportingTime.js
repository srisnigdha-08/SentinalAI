export const REPORT_TIME_ZONE = 'Asia/Kolkata'
export const timeText = value => new Date(value).toLocaleTimeString('en-IN', { hour12: false, timeZone: REPORT_TIME_ZONE })
export const dateText = value => new Date(value).toLocaleDateString('en-IN', { timeZone: REPORT_TIME_ZONE })

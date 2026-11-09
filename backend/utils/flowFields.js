'use strict'
/**
 * Raw flow fields accepted for live detection (POST /api/honeypot/ingest/flow). Same names as the AI
 * engine's Record model (ai-engine/inference/main.py) and demo/replay_cicids.py's CSV mapping; the
 * engine derives payload_entropy and the time features itself.
 */
const FLOW_FIELDS = Object.freeze([
  'flow_duration',
  'total_fwd_packets',
  'total_bwd_packets',
  'total_len_fwd_packets',
  'total_len_bwd_packets',
  'fwd_packet_len_max',
  'fwd_packet_len_min',
  'fwd_packet_len_mean',
  'fwd_packet_len_std',
  'bwd_packet_len_max',
  'bwd_packet_len_min',
  'bwd_packet_len_mean',
  'bwd_packet_len_std',
  'flow_bytes_per_sec',
  'flow_packets_per_sec',
  'flow_iat_mean',
  'flow_iat_std',
  'flow_iat_max',
  'flow_iat_min',
  'fwd_iat_total',
  'fwd_iat_mean',
  'fwd_iat_std',
  'fwd_iat_max',
  'fwd_iat_min',
  'bwd_iat_total',
  'bwd_iat_mean',
  'bwd_iat_std',
  'bwd_iat_max',
  'bwd_iat_min',
  'fwd_psh_flags',
  'bwd_psh_flags',
  'fwd_urg_flags',
  'bwd_urg_flags',
  'fin_flag_count',
  'syn_flag_count',
  'rst_flag_count',
  'psh_flag_count',
  'ack_flag_count',
  'urg_flag_count',
  'fwd_header_len',
  'bwd_header_len',
  'fwd_avg_bytes_per_bulk',
  'bwd_avg_bytes_per_bulk',
  'init_win_bytes_forward',
  'init_win_bytes_backward',
  'active_mean',
  'active_std',
  'idle_mean',
  'idle_std',
  'down_up_ratio',
])

// A flow with fewer real measurements than this would be scored mostly on engine defaults.
const MIN_FLOW_FIELDS = 10

module.exports = { FLOW_FIELDS, MIN_FLOW_FIELDS }

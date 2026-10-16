'use strict'

const path = require('path')
const swaggerJSDoc = require('swagger-jsdoc')
const swaggerUi = require('swagger-ui-express')

const swaggerDefinition = {
  openapi: '3.0.3',
  info: {
    title: 'SentinelAI Backend API',
    version: '1.0.0',
    description:
      'API documentation for SentinelAI — Real-time Autonomous Threat Intelligence, Honeypot Deception & AI Analytics Platform.',
    contact: {
      name: 'SentinelAI Security Team',
      email: 'security@sentinel.io',
    },
  },
  servers: [
    {
      url: '/api',
      description: 'SentinelAI API Base Path',
    },
  ],
  tags: [
    { name: 'Auth', description: 'Authentication and JWT token management' },
    { name: 'Threats', description: 'Threat intelligence, telemetry, and analytics' },
    { name: 'Settings & Blocklist', description: 'Platform configuration, manual IP blocking, and unblocking' },
    { name: 'Honeypot', description: 'Deception nodes and honeypot attacker session telemetry' },
    { name: 'Honeypot Ingest', description: 'Collector telemetry ingestion and real-time auto-blocking checks' },
    { name: 'Campaigns', description: 'Automated threat campaign clustering and Jaccard similarity grouping' },
    { name: 'AI Engine', description: 'AI inference pipeline, attack simulations, and ML model diagnostics' },
    { name: 'Alerts', description: 'Real-time security alert dispatching and triage' },
    { name: 'Users', description: 'User management and role-based access control (Admin)' },
  ],
  components: {
    securitySchemes: {
      BearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Provide JWT token obtained from `/api/auth/login`',
      },
      ApiKeyAuth: {
        type: 'apiKey',
        in: 'header',
        name: 'X-API-Key',
        description: 'Internal service pre-shared key for daemon & collector endpoints',
      },
    },
    schemas: {
      ErrorResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: false },
          error: { type: 'string', example: 'Invalid credentials or resource not found' },
        },
      },
      SuccessResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          message: { type: 'string', example: 'Operation completed successfully' },
        },
      },
      User: {
        type: 'object',
        properties: {
          _id: { type: 'string', example: '65b93d8b1c4e2a0012345678' },
          name: { type: 'string', example: 'Security Analyst' },
          email: { type: 'string', format: 'email', example: 'analyst@sentinel.io' },
          role: { type: 'string', enum: ['admin', 'analyst', 'viewer'], example: 'analyst' },
          status: { type: 'string', enum: ['active', 'inactive', 'suspended'], example: 'active' },
          createdAt: { type: 'string', format: 'date-time' },
          lastLogin: { type: 'string', format: 'date-time' },
        },
      },
      Threat: {
        type: 'object',
        properties: {
          _id: { type: 'string', example: '65b93d8b1c4e2a0012345678' },
          sourceIP: { type: 'string', example: '185.220.101.47' },
          targetPort: { type: 'integer', example: 22 },
          protocol: { type: 'string', example: 'SSH' },
          attackType: { type: 'string', example: 'Brute Force - SSH' },
          severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'], example: 'high' },
          confidenceScore: { type: 'number', minimum: 0, maximum: 1, example: 0.94 },
          status: {
            type: 'string',
            enum: ['detected', 'analyzing', 'mitigated', 'blocked', 'ignored'],
            example: 'blocked',
          },
          timestamp: { type: 'string', format: 'date-time' },
        },
      },
      HoneypotSession: {
        type: 'object',
        properties: {
          _id: { type: 'string', example: '65b93d8b1c4e2a0012345678' },
          sessionId: { type: 'string', example: 'sess-cowrie-1708123456' },
          sourceIP: { type: 'string', example: '194.26.29.112' },
          sourcePort: { type: 'integer', example: 54321 },
          honeypotNode: { type: 'string', example: 'SSH-COWRIE-01' },
          status: { type: 'string', enum: ['active', 'closed', 'terminated'], example: 'closed' },
          startTime: { type: 'string', format: 'date-time' },
          endTime: { type: 'string', format: 'date-time' },
          durationSeconds: { type: 'integer', example: 142 },
          deceptionScore: { type: 'number', example: 85.5 },
          aiClassification: { type: 'string', example: 'MALWARE_DROPPER' },
          aiThreatScore: { type: 'number', example: 0.96 },
        },
      },
      Campaign: {
        type: 'object',
        properties: {
          _id: { type: 'string', example: '65b93d8b1c4e2a0012345678' },
          name: { type: 'string', example: 'Campaign-SSH-BruteForce-T1110' },
          threatActor: { type: 'string', example: 'UNC2452' },
          classification: { type: 'string', example: 'SSH Brute Force & Persistence' },
          severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'], example: 'critical' },
          sessions: { type: 'array', items: { type: 'string' } },
          firstSeen: { type: 'string', format: 'date-time' },
          lastSeen: { type: 'string', format: 'date-time' },
        },
      },
      BlockedIP: {
        type: 'object',
        properties: {
          _id: { type: 'string', example: '65b93d8b1c4e2a0012345678' },
          ip: { type: 'string', example: '185.220.101.47' },
          reason: { type: 'string', example: 'Automated threshold block (AI Threat Score: 0.98)' },
          blockedAt: { type: 'string', format: 'date-time' },
          source: { type: 'string', enum: ['ai_auto', 'manual', 'honeypot'], example: 'ai_auto' },
        },
      },
      Alert: {
        type: 'object',
        properties: {
          _id: { type: 'string', example: '65b93d8b1c4e2a0012345678' },
          title: { type: 'string', example: 'Critical Threat Detected' },
          message: { type: 'string', example: 'IP 185.220.101.47 triggered high severity threshold' },
          severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'], example: 'critical' },
          isRead: { type: 'boolean', example: false },
          createdAt: { type: 'string', format: 'date-time' },
        },
      },
      AIPrediction: {
        type: 'object',
        properties: {
          _id: { type: 'string', example: '65b93d8b1c4e2a0012345678' },
          sourceIP: { type: 'string', example: '194.26.29.112' },
          predictedClass: { type: 'string', example: 'MALWARE_DROPPER' },
          confidence: { type: 'number', example: 0.95 },
          threatScore: { type: 'number', example: 0.92 },
          isVerified: { type: 'boolean', example: false },
          verifiedBy: { type: 'string' },
          actualClass: { type: 'string' },
          createdAt: { type: 'string', format: 'date-time' },
        },
      },
    },
  },
}

const routesPath = path.join(__dirname, '../routes/*.js').replace(/\\/g, '/')

const options = {
  swaggerDefinition,
  apis: [routesPath, './routes/*.js'],
}

const swaggerSpec = swaggerJSDoc(options)

module.exports = { swaggerUi, swaggerSpec }

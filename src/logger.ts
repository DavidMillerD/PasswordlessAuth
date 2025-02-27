export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  NONE = 4
}

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  meta?: any;
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface LoggerConfig {
  level: LogLevel;
  enableConsole?: boolean;
  enableFile?: boolean;
  fileName?: string;
  maxEntries?: number;
  sensitiveFields?: string[];
}

export class AuthLogger {
  private logs: LogEntry[] = [];
  private config: Required<LoggerConfig>;

  constructor(config: Partial<LoggerConfig> = {}) {
    this.config = {
      level: LogLevel.INFO,
      enableConsole: true,
      enableFile: false,
      fileName: 'auth.log',
      maxEntries: 1000,
      sensitiveFields: ['password', 'token', 'secret', 'key'],
      ...config
    };
  }

  private sanitizeData(data: any): any {
    if (typeof data !== 'object' || data === null) {
      return data;
    }

    if (Array.isArray(data)) {
      return data.map(item => this.sanitizeData(item));
    }

    const sanitized: any = {};
    for (const [key, value] of Object.entries(data)) {
      if (this.config.sensitiveFields.includes(key.toLowerCase())) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'object') {
        sanitized[key] = this.sanitizeData(value);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  private log(level: LogLevel, message: string, meta?: any, context?: Partial<LogEntry>): void {
    if (level < this.config.level) {
      return;
    }

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      meta: meta ? this.sanitizeData(meta) : undefined,
      ...context
    };

    // Add to in-memory logs
    this.logs.push(entry);

    // Cleanup old logs if over limit
    if (this.logs.length > this.config.maxEntries) {
      this.logs.splice(0, this.logs.length - this.config.maxEntries);
    }

    // Console output
    if (this.config.enableConsole) {
      const levelName = LogLevel[level];
      const contextInfo = context?.userId ? ` [User: ${context.userId}]` : '';
      console.log(`[${entry.timestamp}] ${levelName}${contextInfo}: ${message}`, meta || '');
    }
  }

  debug(message: string, meta?: any, context?: Partial<LogEntry>): void {
    this.log(LogLevel.DEBUG, message, meta, context);
  }

  info(message: string, meta?: any, context?: Partial<LogEntry>): void {
    this.log(LogLevel.INFO, message, meta, context);
  }

  warn(message: string, meta?: any, context?: Partial<LogEntry>): void {
    this.log(LogLevel.WARN, message, meta, context);
  }

  error(message: string, meta?: any, context?: Partial<LogEntry>): void {
    this.log(LogLevel.ERROR, message, meta, context);
  }

  // Auth-specific logging methods
  logAuthAttempt(email: string, method: 'magic-link' | 'webauthn', success: boolean, context?: Partial<LogEntry>): void {
    const message = `Authentication attempt: ${method} for ${email} - ${success ? 'SUCCESS' : 'FAILED'}`;
    if (success) {
      this.info(message, { email, method }, context);
    } else {
      this.warn(message, { email, method }, context);
    }
  }

  logTokenGeneration(userId: string, tokenType: 'jwt' | 'magic-link', context?: Partial<LogEntry>): void {
    this.info(`Token generated: ${tokenType}`, { userId, tokenType }, context);
  }

  logTokenVerification(success: boolean, reason?: string, context?: Partial<LogEntry>): void {
    const message = `Token verification ${success ? 'succeeded' : 'failed'}`;
    if (success) {
      this.info(message, { reason }, context);
    } else {
      this.warn(message, { reason }, context);
    }
  }

  logSessionActivity(action: 'created' | 'destroyed' | 'refreshed', sessionId: string, context?: Partial<LogEntry>): void {
    this.info(`Session ${action}`, { sessionId, action }, { ...context, sessionId });
  }

  logSecurityEvent(event: string, severity: 'low' | 'medium' | 'high', meta?: any, context?: Partial<LogEntry>): void {
    const message = `Security event: ${event} (${severity} severity)`;
    if (severity === 'high') {
      this.error(message, meta, context);
    } else if (severity === 'medium') {
      this.warn(message, meta, context);
    } else {
      this.info(message, meta, context);
    }
  }

  logRateLimit(identifier: string, action: string, blocked: boolean, context?: Partial<LogEntry>): void {
    const message = `Rate limit ${blocked ? 'exceeded' : 'checked'} for ${action}`;
    if (blocked) {
      this.warn(message, { identifier, action }, context);
    } else {
      this.debug(message, { identifier, action }, context);
    }
  }

  // Query methods
  getLogs(filter?: {
    level?: LogLevel;
    userId?: string;
    sessionId?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }): LogEntry[] {
    let filteredLogs = [...this.logs];

    if (filter) {
      if (filter.level !== undefined) {
        filteredLogs = filteredLogs.filter(log => log.level >= filter.level!);
      }
      
      if (filter.userId) {
        filteredLogs = filteredLogs.filter(log => log.userId === filter.userId);
      }
      
      if (filter.sessionId) {
        filteredLogs = filteredLogs.filter(log => log.sessionId === filter.sessionId);
      }
      
      if (filter.startDate) {
        filteredLogs = filteredLogs.filter(log => new Date(log.timestamp) >= filter.startDate!);
      }
      
      if (filter.endDate) {
        filteredLogs = filteredLogs.filter(log => new Date(log.timestamp) <= filter.endDate!);
      }
      
      if (filter.limit) {
        filteredLogs = filteredLogs.slice(-filter.limit);
      }
    }

    return filteredLogs;
  }

  getStats() {
    const stats = {
      totalLogs: this.logs.length,
      byLevel: {} as Record<string, number>,
      recentActivity: {
        lastHour: 0,
        lastDay: 0
      }
    };

    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    for (const log of this.logs) {
      const levelName = LogLevel[log.level];
      stats.byLevel[levelName] = (stats.byLevel[levelName] || 0) + 1;

      const logTime = new Date(log.timestamp);
      if (logTime > oneHourAgo) {
        stats.recentActivity.lastHour++;
      }
      if (logTime > oneDayAgo) {
        stats.recentActivity.lastDay++;
      }
    }

    return stats;
  }

  clear(): void {
    this.logs = [];
  }
}

// Default logger instance
export const defaultLogger = new AuthLogger();
import { UserInfo } from './types';
import { generateSecureToken } from './utils';

export interface SessionData {
  id: string;
  userId: string;
  userInfo: UserInfo;
  createdAt: Date;
  expiresAt: Date;
  lastAccessAt: Date;
  ipAddress?: string;
  userAgent?: string;
  deviceId?: string;
}

export interface SessionConfig {
  sessionDuration?: number; // in milliseconds
  cleanupInterval?: number; // in milliseconds
  maxSessionsPerUser?: number;
}

export class SessionManager {
  private sessions = new Map<string, SessionData>();
  private userSessions = new Map<string, Set<string>>();
  private cleanupTimer?: NodeJS.Timeout;

  constructor(private config: SessionConfig = {}) {
    const defaultConfig = {
      sessionDuration: 24 * 60 * 60 * 1000, // 24 hours
      cleanupInterval: 60 * 60 * 1000, // 1 hour
      maxSessionsPerUser: 5
    };
    
    this.config = { ...defaultConfig, ...config };
    this.startCleanup();
  }

  createSession(
    userInfo: UserInfo, 
    metadata?: { ipAddress?: string; userAgent?: string; deviceId?: string }
  ): SessionData {
    // Check if user has too many active sessions
    const userSessionIds = this.userSessions.get(userInfo.id) || new Set();
    if (userSessionIds.size >= (this.config.maxSessionsPerUser || 5)) {
      // Remove oldest session
      const oldestSessionId = Array.from(userSessionIds)[0];
      this.destroySession(oldestSessionId);
    }

    const sessionId = generateSecureToken(32);
    const now = new Date();
    const session: SessionData = {
      id: sessionId,
      userId: userInfo.id,
      userInfo: { ...userInfo },
      createdAt: now,
      expiresAt: new Date(now.getTime() + (this.config.sessionDuration || 0)),
      lastAccessAt: now,
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
      deviceId: metadata?.deviceId
    };

    this.sessions.set(sessionId, session);
    
    if (!this.userSessions.has(userInfo.id)) {
      this.userSessions.set(userInfo.id, new Set());
    }
    this.userSessions.get(userInfo.id)!.add(sessionId);

    return session;
  }

  getSession(sessionId: string): SessionData | null {
    const session = this.sessions.get(sessionId);
    
    if (!session) {
      return null;
    }

    if (session.expiresAt < new Date()) {
      this.destroySession(sessionId);
      return null;
    }

    // Update last access time
    session.lastAccessAt = new Date();
    return session;
  }

  refreshSession(sessionId: string, extensionTime?: number): boolean {
    const session = this.sessions.get(sessionId);
    
    if (!session || session.expiresAt < new Date()) {
      return false;
    }

    const extension = extensionTime || this.config.sessionDuration || 0;
    session.expiresAt = new Date(Date.now() + extension);
    session.lastAccessAt = new Date();
    
    return true;
  }

  destroySession(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    
    if (!session) {
      return false;
    }

    this.sessions.delete(sessionId);
    
    const userSessionIds = this.userSessions.get(session.userId);
    if (userSessionIds) {
      userSessionIds.delete(sessionId);
      if (userSessionIds.size === 0) {
        this.userSessions.delete(session.userId);
      }
    }

    return true;
  }

  destroyAllUserSessions(userId: string): number {
    const sessionIds = this.userSessions.get(userId);
    
    if (!sessionIds) {
      return 0;
    }

    let destroyedCount = 0;
    for (const sessionId of sessionIds) {
      if (this.sessions.delete(sessionId)) {
        destroyedCount++;
      }
    }

    this.userSessions.delete(userId);
    return destroyedCount;
  }

  getUserSessions(userId: string): SessionData[] {
    const sessionIds = this.userSessions.get(userId);
    
    if (!sessionIds) {
      return [];
    }

    const sessions: SessionData[] = [];
    for (const sessionId of sessionIds) {
      const session = this.sessions.get(sessionId);
      if (session && session.expiresAt > new Date()) {
        sessions.push(session);
      }
    }

    return sessions;
  }

  getStats() {
    return {
      totalSessions: this.sessions.size,
      activeUsers: this.userSessions.size,
      averageSessionsPerUser: this.userSessions.size > 0 
        ? this.sessions.size / this.userSessions.size 
        : 0
    };
  }

  private startCleanup() {
    if (this.config.cleanupInterval && this.config.cleanupInterval > 0) {
      this.cleanupTimer = setInterval(() => {
        this.cleanup();
      }, this.config.cleanupInterval);
    }
  }

  private cleanup() {
    const now = new Date();
    const expiredSessions: string[] = [];

    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.expiresAt < now) {
        expiredSessions.push(sessionId);
      }
    }

    for (const sessionId of expiredSessions) {
      this.destroySession(sessionId);
    }
  }

  destroy() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }
    this.sessions.clear();
    this.userSessions.clear();
  }
}
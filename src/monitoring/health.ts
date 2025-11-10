/**
 * Health Checker Service
 *
 * Provides comprehensive health checks for all system components
 */

import { HealthCheck } from '../core/types';

export interface HealthCheckConfig {
  name: string;
  description?: string;
  timeout?: number;
  interval?: number;
  critical?: boolean;
}

export class HealthChecker {
  private static instance: HealthChecker;
  private checks: Map<string, HealthCheckConfig> = new Map();
  private checkFunctions: Map<string, () => Promise<HealthCheck>> = new Map();

  private constructor() {}

  public static getInstance(): HealthChecker {
    if (!HealthChecker.instance) {
      HealthChecker.instance = new HealthChecker();
    }
    return HealthChecker.instance;
  }

  /**
   * Register a health check
   */
  public registerCheck(
    name: string,
    checkFn: () => Promise<HealthCheck>,
    config: HealthCheckConfig = {}
  ): void {
    this.checks.set(name, {
      name,
      timeout: 5000, // 5 seconds default
      interval: 30000, // 30 seconds default
      critical: false,
      ...config,
    });

    this.checkFunctions.set(name, checkFn);
  }

  /**
   * Run all health checks
   */
  public async runAllChecks(): Promise<HealthCheck[]> {
    const results: HealthCheck[] = [];

    for (const [name, config] of this.checks.entries()) {
      try {
        const checkFn = this.checkFunctions.get(name);
        if (!checkFn) continue;

        const result = await Promise.race([
          checkFn(),
          this.createTimeoutCheck(config),
        ]);

        results.push(result);
      } catch (error) {
        results.push({
          name: config.name,
          status: 'unhealthy',
          message: `Health check failed: ${error.message}`,
          timestamp: new Date(),
        });
      }
    }

    return results;
  }

  /**
   * Run a specific health check
   */
  public async runCheck(name: string): Promise<HealthCheck | null> {
    const checkFn = this.checkFunctions.get(name);
    const config = this.checks.get(name);

    if (!checkFn || !config) {
      return null;
    }

    try {
      return await Promise.race([
        checkFn(),
        this.createTimeoutCheck(config),
      ]);
    } catch (error) {
      return {
        name: config.name,
        status: 'unhealthy',
        message: `Health check failed: ${error.message}`,
        timestamp: new Date(),
      };
    }
  }

  /**
   * Get overall system health
   */
  public async getOverallHealth(): Promise<HealthCheck> {
    const checks = await this.runAllChecks();
    const criticalChecks = checks.filter(check =>
      this.checks.get(check.name)?.critical
    );

    const hasCriticalFailure = criticalChecks.some(check => check.status === 'unhealthy');
    const hasAnyFailure = checks.some(check => check.status === 'unhealthy');
    const hasDegraded = checks.some(check => check.status === 'degraded');

    let status: 'healthy' | 'unhealthy' | 'degraded' = 'healthy';
    let message = 'All systems operational';

    if (hasCriticalFailure) {
      status = 'unhealthy';
      message = 'Critical system failure detected';
    } else if (hasAnyFailure || hasDegraded) {
      status = hasAnyFailure ? 'unhealthy' : 'degraded';
      message = hasAnyFailure ? 'Some systems are failing' : 'Some systems are degraded';
    }

    return {
      name: 'system',
      status,
      message,
      timestamp: new Date(),
      details: checks.reduce((acc, check) => {
        acc[check.name] = check;
        return acc;
      }, {} as Record<string, HealthCheck>),
    };
  }

  /**
   * Create timeout check
   */
  private async createTimeoutCheck(config: HealthCheckConfig): Promise<HealthCheck> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Health check timeout after ${config.timeout}ms`));
      }, config.timeout);
    });
  }

  // Built-in health check functions

  /**
   * Database health check
   */
  public static createDatabaseCheck(
    name: string,
    checkFn: () => Promise<boolean>
  ): () => Promise<HealthCheck> {
    return async (): Promise<HealthCheck> => {
      try {
        const isHealthy = await checkFn();

        return {
          name,
          status: isHealthy ? 'healthy' : 'unhealthy',
          message: isHealthy ? 'Database connection successful' : 'Database connection failed',
          timestamp: new Date(),
          details: { connected: isHealthy },
        };
      } catch (error) {
        return {
          name,
          status: 'unhealthy',
          message: `Database check failed: ${error.message}`,
          timestamp: new Date(),
          details: { error: error.message },
        };
      }
    };
  }

  /**
   * Redis health check
   */
  public static createRedisCheck(
    name: string,
    redisClient: any
  ): () => Promise<HealthCheck> {
    return async (): Promise<HealthCheck> => {
      try {
        await redisClient.ping();
        return {
          name,
          status: 'healthy',
          message: 'Redis connection successful',
          timestamp: new Date(),
          details: { connected: true },
        };
      } catch (error) {
        return {
          name,
          status: 'unhealthy',
          message: `Redis check failed: ${error.message}`,
          timestamp: new Date(),
          details: { connected: false, error: error.message },
        };
      }
    };
  }

  /**
   * External service health check
   */
  public static createHttpCheck(
    name: string,
    url: string,
    options: {
      timeout?: number;
      expectedStatus?: number;
      headers?: Record<string, string>;
    } = {}
  ): () => Promise<HealthCheck> {
    return async (): Promise<HealthCheck> => {
      const startTime = Date.now();

      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), options.timeout || 5000);

        const response = await fetch(url, {
          method: 'GET',
          headers: options.headers || {},
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        const responseTime = Date.now() - startTime;
        const expectedStatus = options.expectedStatus || 200;
        const isHealthy = response.status === expectedStatus;

        return {
          name,
          status: isHealthy ? 'healthy' : 'unhealthy',
          message: isHealthy
            ? `HTTP check successful (${responseTime}ms)`
            : `HTTP check failed: status ${response.status}`,
          timestamp: new Date(),
          details: {
            url,
            status: response.status,
            responseTime,
            expectedStatus,
          },
        };
      } catch (error) {
        const responseTime = Date.now() - startTime;
        return {
          name,
          status: 'unhealthy',
          message: `HTTP check failed: ${error.message}`,
          timestamp: new Date(),
          details: {
            url,
            responseTime,
            error: error.message,
          },
        };
      }
    };
  }

  /**
   * Memory usage health check
   */
  public static createMemoryCheck(
    name: string,
    thresholds: {
      warning?: number; // MB
      critical?: number; // MB
    } = {}
  ): () => Promise<HealthCheck> {
    return async (): Promise<HealthCheck> => {
      const memUsage = process.memoryUsage();
      const usedMB = Math.round(memUsage.heapUsed / 1024 / 1024);
      const totalMB = Math.round(memUsage.heapTotal / 1024 / 1024);

      const warningThreshold = thresholds.warning || 500; // 500MB default
      const criticalThreshold = thresholds.critical || 1000; // 1GB default

      let status: 'healthy' | 'unhealthy' | 'degraded' = 'healthy';
      let message = `Memory usage: ${usedMB}MB / ${totalMB}MB`;

      if (usedMB >= criticalThreshold) {
        status = 'unhealthy';
        message = `Critical memory usage: ${usedMB}MB / ${totalMB}MB`;
      } else if (usedMB >= warningThreshold) {
        status = 'degraded';
        message = `High memory usage: ${usedMB}MB / ${totalMB}MB`;
      }

      return {
        name,
        status,
        message,
        timestamp: new Date(),
        details: {
          used: usedMB,
          total: totalMB,
          percentage: Math.round((usedMB / totalMB) * 100),
          rss: Math.round(memUsage.rss / 1024 / 1024),
          external: Math.round(memUsage.external / 1024 / 1024),
        },
      };
    };
  }

  /**
   * Disk space health check
   */
  public static createDiskCheck(
    name: string,
    path: string = '/',
    thresholds: {
      warning?: number; // percentage
      critical?: number; // percentage
    } = {}
  ): () => Promise<HealthCheck> {
    return async (): Promise<HealthCheck> => {
      try {
        // Note: This is a simplified check. In production, use a library like 'diskusage'
        // For now, we'll simulate disk check
        const usage = await this.getDiskUsage(path);

        const warningThreshold = thresholds.warning || 80;
        const criticalThreshold = thresholds.critical || 95;

        let status: 'healthy' | 'unhealthy' | 'degraded' = 'healthy';
        let message = `Disk usage: ${usage.usedPercentage}%`;

        if (usage.usedPercentage >= criticalThreshold) {
          status = 'unhealthy';
          message = `Critical disk usage: ${usage.usedPercentage}%`;
        } else if (usage.usedPercentage >= warningThreshold) {
          status = 'degraded';
          message = `High disk usage: ${usage.usedPercentage}%`;
        }

        return {
          name,
          status,
          message,
          timestamp: new Date(),
          details: usage,
        };
      } catch (error) {
        return {
          name,
          status: 'unhealthy',
          message: `Disk check failed: ${error.message}`,
          timestamp: new Date(),
          details: { error: error.message },
        };
      }
    };
  }

  /**
   * Get disk usage (simplified implementation)
   */
  private static async getDiskUsage(path: string): Promise<{
    used: number;
    available: number;
    total: number;
    usedPercentage: number;
  }> {
    // In a real implementation, use a library like 'diskusage' or 'fs.statvfs'
    // For now, return mock data
    return {
      used: 50,
      available: 50,
      total: 100,
      usedPercentage: 50,
    };
  }

  /**
   * Custom health check helper
   */
  public static createCustomCheck(
    name: string,
    checkFn: () => Promise<{ healthy: boolean; message?: string; details?: any }>
  ): () => Promise<HealthCheck> {
    return async (): Promise<HealthCheck> => {
      try {
        const result = await checkFn();

        return {
          name,
          status: result.healthy ? 'healthy' : 'unhealthy',
          message: result.message || (result.healthy ? 'Check passed' : 'Check failed'),
          timestamp: new Date(),
          details: result.details,
        };
      } catch (error) {
        return {
          name,
          status: 'unhealthy',
          message: `Custom check failed: ${error.message}`,
          timestamp: new Date(),
          details: { error: error.message },
        };
      }
    };
  }
}

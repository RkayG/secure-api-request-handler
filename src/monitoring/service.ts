/**
 * Monitoring Service
 *
 * Provides comprehensive monitoring, observability, and health checks
 * for the secure API framework.
 */

import { Metric, TraceSpan, TraceEvent, HealthCheck } from '../core/types';

export interface MonitoringConfig {
  provider?: 'console' | 'datadog' | 'newrelic' | 'prometheus';
  serviceName?: string;
  environment?: string;
  apiKey?: string;
  enableTracing?: boolean;
  enableMetrics?: boolean;
  enableHealthChecks?: boolean;
}

export interface SpanContext {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
}

export class MonitoringService {
  private static instance: MonitoringService;
  private config: MonitoringConfig;
  private spans = new Map<string, TraceSpan>();
  private metrics: Metric[] = [];
  private healthChecks: HealthCheck[] = [];

  private constructor(config: MonitoringConfig = {}) {
    this.config = {
      provider: 'console',
      serviceName: 'secure-api-handler',
      environment: process.env.NODE_ENV || 'development',
      enableTracing: true,
      enableMetrics: true,
      enableHealthChecks: true,
      ...config,
    };
  }

  public static getInstance(config?: MonitoringConfig): MonitoringService {
    if (!MonitoringService.instance) {
      MonitoringService.instance = new MonitoringService(config);
    }
    return MonitoringService.instance;
  }

  /**
   * Record a metric
   */
  public recordMetric(
    name: string,
    value: number,
    labels: Record<string, string> = {},
    timestamp?: Date
  ): void {
    const metric: Metric = {
      name,
      value,
      type: this.inferMetricType(name),
      labels: {
        service: this.config.serviceName!,
        environment: this.config.environment!,
        ...labels,
      },
      timestamp: timestamp || new Date(),
    };

    this.metrics.push(metric);

    // Send to monitoring provider
    this.sendMetric(metric);

    // Keep only recent metrics (last 1000)
    if (this.metrics.length > 1000) {
      this.metrics = this.metrics.slice(-500);
    }
  }

  /**
   * Start a new trace span
   */
  public startSpan(
    name: string,
    attributes: Record<string, any> = {},
    parentContext?: SpanContext
  ): string {
    const spanId = this.generateSpanId();
    const traceId = parentContext?.traceId || this.generateTraceId();

    const span: TraceSpan = {
      id: spanId,
      name,
      startTime: new Date(),
      attributes: {
        service: this.config.serviceName,
        environment: this.config.environment,
        ...attributes,
      },
      events: [],
      status: 'ok',
    };

    if (parentContext) {
      span.attributes.parentSpanId = parentContext.spanId;
    }

    this.spans.set(spanId, span);

    // Send span start event
    this.sendSpanEvent('start', span);

    return spanId;
  }

  /**
   * End a trace span
   */
  public endSpan(spanId: string, status: 'ok' | 'error' = 'ok', errorMessage?: string): void {
    const span = this.spans.get(spanId);
    if (!span) {
      console.warn(`Span ${spanId} not found`);
      return;
    }

    span.endTime = new Date();
    span.duration = span.endTime.getTime() - span.startTime.getTime();
    span.status = status;

    if (errorMessage) {
      span.attributes.error = errorMessage;
    }

    // Send span end event
    this.sendSpanEvent('end', span);

    // Remove span from memory after sending
    setTimeout(() => {
      this.spans.delete(spanId);
    }, 100);
  }

  /**
   * Add an event to a span
   */
  public addSpanEvent(spanId: string, name: string, attributes: Record<string, any> = {}): void {
    const span = this.spans.get(spanId);
    if (!span) return;

    const event: TraceEvent = {
      name,
      timestamp: new Date(),
      attributes,
    };

    span.events.push(event);
  }

  /**
   * Record an error
   */
  public recordError(
    error: Error,
    context: Record<string, any> = {},
    spanId?: string
  ): void {
    const errorData = {
      name: error.name,
      message: error.message,
      stack: error.stack,
      ...context,
    };

    this.recordMetric('error.count', 1, {
      error_type: error.name,
      error_message: error.message.substring(0, 100),
    });

    if (spanId) {
      this.addSpanEvent(spanId, 'error', errorData);
    }

    this.sendError(errorData);
  }

  /**
   * Add a health check
   */
  public addHealthCheck(
    name: string,
    checkFn: () => Promise<HealthCheck>
  ): void {
    // Run health check immediately and schedule periodic checks
    this.runHealthCheck(name, checkFn);

    if (this.config.enableHealthChecks) {
      setInterval(() => {
        this.runHealthCheck(name, checkFn);
      }, 30000); // Check every 30 seconds
    }
  }

  private async runHealthCheck(
    name: string,
    checkFn: () => Promise<HealthCheck>
  ): Promise<void> {
    try {
      const check = await checkFn();
      const existingIndex = this.healthChecks.findIndex(hc => hc.name === name);

      if (existingIndex >= 0) {
        this.healthChecks[existingIndex] = check;
      } else {
        this.healthChecks.push(check);
      }

      this.recordMetric('health_check.status', check.status === 'healthy' ? 1 : 0, {
        check_name: name,
        status: check.status,
      });

    } catch (error) {
      console.error(`Health check ${name} failed:`, error);
      this.recordMetric('health_check.error', 1, {
        check_name: name,
      });
    }
  }

  /**
   * Get all health checks
   */
  public getHealthChecks(): HealthCheck[] {
    return [...this.healthChecks];
  }

  /**
   * Get overall health status
   */
  public getOverallHealth(): HealthCheck {
    const checks = this.getHealthChecks();
    const hasUnhealthy = checks.some(check => check.status === 'unhealthy');
    const hasDegraded = checks.some(check => check.status === 'degraded');

    return {
      name: 'overall',
      status: hasUnhealthy ? 'unhealthy' : hasDegraded ? 'degraded' : 'healthy',
      message: hasUnhealthy
        ? 'Some services are unhealthy'
        : hasDegraded
        ? 'Some services are degraded'
        : 'All services are healthy',
      timestamp: new Date(),
      details: checks.reduce((acc, check) => {
        acc[check.name] = check;
        return acc;
      }, {} as Record<string, HealthCheck>),
    };
  }

  /**
   * Get recent metrics
   */
  public getMetrics(limit: number = 100): Metric[] {
    return this.metrics.slice(-limit);
  }

  /**
   * Get active spans
   */
  public getActiveSpans(): TraceSpan[] {
    return Array.from(this.spans.values()).filter(span => !span.endTime);
  }

  // Private methods

  private inferMetricType(name: string): Metric['type'] {
    if (name.includes('count') || name.includes('total')) return 'counter';
    if (name.includes('duration') || name.includes('time')) return 'histogram';
    if (name.includes('size') || name.includes('usage')) return 'gauge';
    return 'counter'; // Default
  }

  private generateTraceId(): string {
    return `trace_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateSpanId(): string {
    return `span_${Math.random().toString(36).substr(2, 9)}`;
  }

  private sendMetric(metric: Metric): void {
    switch (this.config.provider) {
      case 'console':
        console.log(`[METRIC] ${metric.name}: ${metric.value}`, metric.labels);
        break;
      case 'datadog':
        this.sendToDatadog(metric);
        break;
      case 'newrelic':
        this.sendToNewRelic(metric);
        break;
      case 'prometheus':
        this.sendToPrometheus(metric);
        break;
    }
  }

  private sendSpanEvent(type: 'start' | 'end', span: TraceSpan): void {
    if (!this.config.enableTracing) return;

    switch (this.config.provider) {
      case 'console':
        console.log(`[SPAN ${type.toUpperCase()}] ${span.name}`, {
          spanId: span.id,
          duration: span.duration,
          attributes: span.attributes,
        });
        break;
      case 'datadog':
        this.sendSpanToDatadog(type, span);
        break;
      case 'newrelic':
        this.sendSpanToNewRelic(type, span);
        break;
    }
  }

  private sendError(error: any): void {
    switch (this.config.provider) {
      case 'console':
        console.error('[ERROR]', error);
        break;
      case 'datadog':
        this.sendErrorToDatadog(error);
        break;
      case 'newrelic':
        this.sendErrorToNewRelic(error);
        break;
    }
  }

  // Provider-specific implementations (stubs for actual implementation)

  private sendToDatadog(metric: Metric): void {
    // Implementation would send to Datadog API
    console.log('Sending metric to Datadog:', metric);
  }

  private sendToNewRelic(metric: Metric): void {
    // Implementation would send to New Relic API
    console.log('Sending metric to New Relic:', metric);
  }

  private sendToPrometheus(metric: Metric): void {
    // Implementation would expose metrics for Prometheus scraping
    console.log('Exposing metric for Prometheus:', metric);
  }

  private sendSpanToDatadog(type: 'start' | 'end', span: TraceSpan): void {
    console.log('Sending span to Datadog:', type, span);
  }

  private sendSpanToNewRelic(type: 'start' | 'end', span: TraceSpan): void {
    console.log('Sending span to New Relic:', type, span);
  }

  private sendErrorToDatadog(error: any): void {
    console.log('Sending error to Datadog:', error);
  }

  private sendErrorToNewRelic(error: any): void {
    console.log('Sending error to New Relic:', error);
  }
}

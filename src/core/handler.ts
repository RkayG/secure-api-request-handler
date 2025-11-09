/**
 * Core API Handler Framework
 *
 * High-level abstraction for creating consistent, secure API routes with
 * authentication, validation, ownership checks, sanitization, encryption,
 * rate limiting, caching, and observability.
 */

import { z } from 'zod';
import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';

import {
  HandlerConfig,
  HandlerContext,
  User,
  TenantContext,
  TraceContext,
} from './types';
import {
  successResponse,
  errorResponse,
  validationErrorResponse,
  unauthorizedResponse,
  forbiddenResponse,
  rateLimitResponse,
  internalErrorResponse,
} from './response';

// Import services (will be implemented)
import { AuthManager } from '../auth/manager';
import { SanitizationService } from '../security/sanitization';
import { EncryptionService } from '../security/encryption';
import { RedisRateLimiter } from '../security/rate-limiting';
import { CacheManager } from '../caching/manager';
import { MonitoringService } from '../monitoring/service';
import { TenantManager } from '../multitenancy/manager';
import { VersionManager } from '../versioning/manager';
import { ConfigManager } from '../config/manager';

// ============================================
// Main Handler Factory
// ============================================

/**
 * Create a standardized API handler
 *
 * Automatically handles:
 * - Authentication & Authorization
 * - Input validation & sanitization
 * - Resource ownership verification
 * - Rate limiting
 * - Caching
 * - Error handling & monitoring
 * - Multi-tenancy
 * - API versioning
 *
 * @example
 * ```typescript
 * export const POST = createHandler({
 *   schema: z.object({ name: z.string() }),
 *   requireAuth: true,
 *   requireOwnership: {
 *     table: 'experiences',
 *     resourceIdParam: 'id',
 *     selectColumns: 'id, name, brand_id'
 *   },
 *   handler: async ({ input, user, supabase, resource }) => {
 *     const experience = await updateExperience(input, user.brand_id);
 *     return experience;
 *   },
 * });
 * ```
 */
export function createHandler<TInput = unknown, TOutput = unknown>(
  config: HandlerConfig<TInput, TOutput>
) {
  return async (
    req: NextRequest,
    context?: { params: Promise<Record<string, string>> }
  ): Promise<NextResponse> => {
    const traceId = generateTraceId();
    const startTime = Date.now();

    // Initialize services
    const monitoring = MonitoringService.getInstance();
    const configManager = ConfigManager.getInstance();
    const tenantManager = TenantManager.getInstance();
    const versionManager = VersionManager.getInstance();

    let span: any = null;

    try {
      // Start monitoring span
      if (config.monitoring?.enableTracing) {
        span = monitoring.startSpan('handler', { traceId });
      }

      const params = context?.params ? await context.params : {};
      const searchParams = req.nextUrl.searchParams;

      // ============================================
      // 1. Configuration & Feature Flags
      // ============================================

      if (config.featureFlags) {
        const featureFlags = configManager.getFeatureFlags();
        const disabledFeatures = config.featureFlags.filter(
          flag => !featureFlags[flag]
        );

        if (disabledFeatures.length > 0) {
          return errorResponse(
            'SERVICE_UNAVAILABLE',
            `Feature ${disabledFeatures[0]} is disabled`,
            503
          );
        }
      }

      // ============================================
      // 2. API Versioning
      // ============================================

      if (config.apiVersion) {
        const clientVersion = versionManager.getClientVersion(req);
        if (!versionManager.isVersionSupported(clientVersion, config.apiVersion)) {
          return errorResponse(
            'BAD_REQUEST',
            `API version ${clientVersion} is not supported. Required: ${config.apiVersion}`,
            400
          );
        }
      }

      // ============================================
      // 3. Multi-Tenant Context
      // ============================================

      let tenant: TenantContext | undefined;

      if (configManager.getConfig().multitenancy.enabled) {
        tenant = await tenantManager.getTenantFromRequest(req);
        if (!tenant) {
          return errorResponse('BAD_REQUEST', 'Invalid tenant', 400);
        }
      }

      // ============================================
      // 4. Authentication
      // ============================================

      let user: User | null = null;

      if (config.requireAuth) {
        const authManager = AuthManager.getInstance();
        const strategies = config.authStrategies || ['jwt'];

        user = await authManager.authenticate(req, strategies);

        if (!user) {
          monitoring.recordMetric('auth.failure', 1, {
            method: req.method,
            path: req.nextUrl.pathname,
          });
          return unauthorizedResponse('Authentication required');
        }

        monitoring.recordMetric('auth.success', 1, {
          method: req.method,
          user_role: user.role,
        });

        // Role-based access control
        if (config.allowedRoles && config.allowedRoles.length > 0) {
          const userRole = user?.role || 'user';
          if (!config.allowedRoles.includes(userRole)) {
            monitoring.recordMetric('auth.forbidden', 1, {
              required_roles: config.allowedRoles.join(','),
              user_role: userRole,
            });
            return forbiddenResponse('Insufficient permissions for this operation');
          }
        }

        // Permission-based access control
        if (config.requiredPermissions && config.requiredPermissions.length > 0) {
          const hasPermissions = config.requiredPermissions.every(
            permission => user?.permissions?.includes(permission)
          );

          if (!hasPermissions) {
            monitoring.recordMetric('auth.forbidden', 1, {
              required_permissions: config.requiredPermissions.join(','),
            });
            return forbiddenResponse('Missing required permissions');
          }
        }
      }

      // ============================================
      // 5. Rate Limiting
      // ============================================

      if (config.rateLimit) {
        const rateLimiter = RedisRateLimiter.getInstance();
        const key = config.rateLimit.keyGenerator
          ? config.rateLimit.keyGenerator(req, user || undefined)
          : `rate-limit:${user?.id || req.ip}:${req.nextUrl.pathname}`;

        const isAllowed = await rateLimiter.checkLimit(key, config.rateLimit);

        if (!isAllowed) {
          monitoring.recordMetric('rate_limit.exceeded', 1, {
            key,
            method: req.method,
            path: req.nextUrl.pathname,
          });
          return rateLimitResponse('Rate limit exceeded');
        }
      }

      // ============================================
      // 6. Input Validation & Sanitization
      // ============================================

      let input: TInput;

      if (config.schema) {
        try {
          // Parse request body for non-GET requests
          const body = req.method !== 'GET' ? await req.json() : {};

          // Combine body and query params for validation
          const rawInput = {
            ...body,
            ...Object.fromEntries(searchParams),
          };

          // Sanitize input
          const sanitizationService = SanitizationService.getInstance();
          const sanitizedInput = await sanitizationService.sanitize(rawInput);

          // Validate with Zod
          const parseResult = config.schema.safeParse(sanitizedInput);

          if (!parseResult.success) {
            const details = parseResult.error.flatten().fieldErrors;
            monitoring.recordMetric('validation.error', 1, {
              field_count: Object.keys(details).length,
            });
            return validationErrorResponse('Invalid input data', details);
          }

          input = parseResult.data;
        } catch (error) {
          if (error instanceof SyntaxError) {
            return validationErrorResponse('Invalid JSON in request body');
          }
          throw error;
        }
      } else {
        input = {} as TInput;
      }

      // ============================================
      // 7. Cache Check
      // ============================================

      if (config.cache && req.method === 'GET') {
        const cacheManager = CacheManager.getInstance();
        const cacheKey = config.cache.keyGenerator
          ? config.cache.keyGenerator(req, user || undefined)
          : `cache:${req.nextUrl.pathname}:${JSON.stringify(input)}`;

        const cached = await cacheManager.get(cacheKey);
        if (cached) {
          monitoring.recordMetric('cache.hit', 1, {
            key: cacheKey,
          });

          const executionTime = Date.now() - startTime;
          return successResponse(cached, undefined, 200, {
            executionTime,
            cached: true,
          });
        }

        monitoring.recordMetric('cache.miss', 1, {
          key: cacheKey,
        });
      }

      // ============================================
      // 8. Database Connection
      // ============================================

      let supabase: any;

      if (tenant) {
        // Get tenant-specific connection
        supabase = await tenantManager.getDatabaseConnection(tenant.id);
      } else {
        // Get default connection
        supabase = createClient(
          process.env.NEXT_PUBLIC_SUPABASE_URL!,
          process.env.SUPABASE_SERVICE_ROLE_KEY!
        );
      }

      // ============================================
      // 9. Resource Ownership Verification
      // ============================================

      let resource: any = undefined;

      if (config.requireOwnership && user) {
        const { table, resourceIdParam, resourceIdColumn, brandIdColumn, tenantIdColumn, selectColumns } = config.requireOwnership;
        const resourceId = params[resourceIdParam];

        if (!resourceId) {
          return validationErrorResponse(`Missing required parameter: ${resourceIdParam}`);
        }

        // Build ownership query
        let query = supabase.from(table).select(selectColumns || '*');

        // Add resource ID filter
        const resourceColumn = resourceIdColumn || 'id';
        query = query.eq(resourceColumn, resourceId);

        // Add brand/tenant ownership filter
        if (brandIdColumn && user.brand_id) {
          query = query.eq(brandIdColumn, user.brand_id);
        }

        if (tenantIdColumn && tenant?.id) {
          query = query.eq(tenantIdColumn, tenant.id);
        }

        const { data, error } = await query.single();

        if (error || !data) {
          monitoring.recordMetric('ownership.verification_failed', 1, {
            table,
            resource_id: resourceId,
          });
          return forbiddenResponse('Resource not found or access denied');
        }

        resource = data;
      }

      // ============================================
      // 10. Execute Handler
      // ============================================

      const handlerContext: HandlerContext<TInput> = {
        input,
        user,
        supabase,
        params,
        searchParams,
        request: req,
        resource,
        tenant,
        trace: {
          traceId,
          spanId: generateSpanId(),
          startTime: new Date(startTime),
          tags: {
            method: req.method,
            path: req.nextUrl.pathname,
            user_id: user?.id,
            tenant_id: tenant?.id,
          },
        },
      };

      const result = await config.handler(handlerContext);

      // ============================================
      // 11. Auto-sanitize and encrypt response
      // ============================================

      let processedResult = result;

      // Sanitize response
      const shouldSanitize = config.sanitizeResponse !== false;
      if (shouldSanitize) {
        const sanitizationService = SanitizationService.getInstance();
        processedResult = await sanitizationService.sanitizeResponse(processedResult);
        monitoring.recordMetric('sanitization.applied', 1);
      }

      // Encrypt sensitive fields if configured
      const encryptionService = EncryptionService.getInstance();
      processedResult = await encryptionService.processResponse(processedResult);

      // ============================================
      // 12. Cache Result
      // ============================================

      if (config.cache && req.method === 'GET') {
        const cacheManager = CacheManager.getInstance();
        const cacheKey = config.cache.keyGenerator
          ? config.cache.keyGenerator(req, user || undefined)
          : `cache:${req.nextUrl.pathname}:${JSON.stringify(input)}`;

        await cacheManager.set(cacheKey, processedResult, config.cache.ttl);
      }

      // ============================================
      // 13. Success Response
      // ============================================

      const executionTime = Date.now() - startTime;
      monitoring.recordMetric('handler.success', 1, {
        method: req.method,
        path: req.nextUrl.pathname,
        execution_time: executionTime,
      });

      return successResponse(processedResult, undefined, config.successStatus, {
        executionTime,
      });

    } catch (error: any) {
      const executionTime = Date.now() - startTime;

      // Record error metrics
      monitoring.recordMetric('handler.error', 1, {
        method: req.method,
        path: req.nextUrl.pathname,
        error_type: error.constructor.name,
        execution_time: executionTime,
      });

      console.error('[API Handler Error]', {
        method: req.method,
        url: req.url,
        error: error.message,
        traceId,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
      });

      // Close monitoring span
      if (span) {
        monitoring.endSpan(span, 'error', error.message);
      }

      // Zod validation errors
      if (error instanceof z.ZodError) {
        return validationErrorResponse(
          'Validation failed',
          error.flatten().fieldErrors
        );
      }

      // Return generic error (don't expose internal details)
      return internalErrorResponse(
        process.env.NODE_ENV === 'development'
          ? `Internal error: ${error.message}`
          : 'An unexpected error occurred'
      );
    } finally {
      // End monitoring span
      if (span) {
        monitoring.endSpan(span);
      }
    }
  };
}

// ============================================
// Convenience Wrappers
// ============================================

/**
 * Create an authenticated handler (requires login)
 */
export const createAuthenticatedHandler = <TInput, TOutput>(
  config: Omit<HandlerConfig<TInput, TOutput>, 'requireAuth'>
): ReturnType<typeof createHandler<TInput, TOutput>> => {
  return createHandler({ ...config, requireAuth: true });
};

/**
 * Create a public handler (no authentication required)
 */
export const createPublicHandler = <TInput, TOutput>(
  config: Omit<HandlerConfig<TInput, TOutput>, 'requireAuth'>
): ReturnType<typeof createHandler<TInput, TOutput>> => {
  return createHandler({ ...config, requireAuth: false });
};

/**
 * Create an admin-only handler
 */
export const createAdminHandler = <TInput, TOutput>(
  config: Omit<HandlerConfig<TInput, TOutput>, 'requireAuth' | 'allowedRoles'>
): ReturnType<typeof createHandler<TInput, TOutput>> => {
  return createHandler({
    ...config,
    requireAuth: true,
    allowedRoles: ['admin'],
  });
};

/**
 * Create a tenant-scoped handler
 */
export const createTenantHandler = <TInput, TOutput>(
  config: Omit<HandlerConfig<TInput, TOutput>, 'requireAuth'>
): ReturnType<typeof createHandler<TInput, TOutput>> => {
  return createHandler({
    ...config,
    requireAuth: true,
    featureFlags: ['multitenancy'],
  });
};

// ============================================
// Utility Functions
// ============================================

function generateTraceId(): string {
  return `trace_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function generateSpanId(): string {
  return `span_${Math.random().toString(36).substr(2, 9)}`;
}

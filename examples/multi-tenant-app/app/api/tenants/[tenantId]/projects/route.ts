/**
 * Multi-Tenant API Example - Project Management
 *
 * This example demonstrates multi-tenant functionality with
 * tenant isolation, resource ownership, and cross-tenant security.
 */

import { z } from 'zod';
import {
  createTenantHandler,
  createAuthenticatedHandler,
  TenantManager,
  MonitoringService,
} from '../../../../src';

// Validation schemas
const CreateProjectSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(1000).optional(),
  status: z.enum(['planning', 'active', 'completed', 'archived']).default('planning'),
  priority: z.enum(['low', 'medium', 'high', 'urgent']).default('medium'),
  tags: z.array(z.string()).max(10).optional(),
});

const UpdateProjectSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  description: z.string().max(1000).optional(),
  status: z.enum(['planning', 'active', 'completed', 'archived']).optional(),
  priority: z.enum(['low', 'medium', 'high', 'urgent']).optional(),
  tags: z.array(z.string()).max(10).optional(),
});

// ============================================
// Tenant-Scoped Routes
// ============================================

/**
 * GET /api/tenants/[tenantId]/projects - List tenant projects
 */
export const GET = createTenantHandler({
  schema: z.object({
    status: z.enum(['planning', 'active', 'completed', 'archived']).optional(),
    priority: z.enum(['low', 'medium', 'high', 'urgent']).optional(),
    limit: z.number().min(1).max(100).default(20),
    offset: z.number().min(0).default(0),
    search: z.string().optional(),
    sortBy: z.enum(['name', 'created_at', 'updated_at', 'priority']).default('created_at'),
    sortOrder: z.enum(['asc', 'desc']).default('desc'),
  }),
  cache: {
    ttl: 300, // 5 minutes
    keyGenerator: (req, user) => {
      const params = req.nextUrl.searchParams;
      return `tenant:${req.params?.tenantId}:projects:${params.toString()}`;
    },
  },
  handler: async ({ input, tenant, supabase, user }) => {
    const { status, priority, limit, offset, search, sortBy, sortOrder } = input;

    // Build query for tenant's projects
    let query = supabase
      .from('projects')
      .select(`
        id,
        name,
        description,
        status,
        priority,
        tags,
        created_at,
        updated_at,
        created_by,
        updated_by,
        member_count:members(count)
      `, { count: 'exact' })
      .eq('tenant_id', tenant.id);

    // Apply filters
    if (status) {
      query = query.eq('status', status);
    }

    if (priority) {
      query = query.eq('priority', priority);
    }

    if (search) {
      query = query.or(`name.ilike.%${search}%,description.ilike.%${search}%`);
    }

    // Apply sorting
    const sortColumn = sortBy === 'created_at' ? 'created_at' :
                      sortBy === 'updated_at' ? 'updated_at' :
                      sortBy === 'priority' ? 'priority' : 'name';

    query = query.order(sortColumn, { ascending: sortOrder === 'asc' });

    // Apply pagination
    query = query.range(offset, offset + limit - 1);

    const { data, error, count } = await query;

    if (error) throw error;

    // Record metrics
    const monitoring = MonitoringService.getInstance();
    monitoring.recordMetric('projects.listed', data.length, {
      tenant_id: tenant.id,
      user_id: user?.id,
    });

    return {
      projects: data,
      pagination: {
        limit,
        offset,
        total: count,
        hasMore: offset + limit < (count || 0),
      },
    };
  },
});

/**
 * POST /api/tenants/[tenantId]/projects - Create project
 */
export const POST = createTenantHandler({
  schema: CreateProjectSchema,
  rateLimit: {
    windowMs: 60000, // 1 minute
    maxRequests: 10, // 10 projects per minute per user
    keyGenerator: (req, user) => `create-project:${user?.id}`,
  },
  handler: async ({ input, tenant, user, supabase }) => {
    // Check tenant's project limit
    const { count: projectCount } = await supabase
      .from('projects')
      .select('*', { count: 'exact', head: true })
      .eq('tenant_id', tenant.id);

    const tenantManager = TenantManager.getInstance();
    const tenantLimits = await tenantManager.getTenantLimits(tenant.id);

    if (projectCount >= tenantLimits.maxProjects) {
      throw new Error('Project limit reached for this tenant');
    }

    // Create project
    const { data: project, error: projectError } = await supabase
      .from('projects')
      .insert({
        ...input,
        tenant_id: tenant.id,
        created_by: user?.id,
      })
      .select()
      .single();

    if (projectError) throw projectError;

    // Add creator as project member with admin role
    const { error: memberError } = await supabase
      .from('project_members')
      .insert({
        project_id: project.id,
        user_id: user?.id,
        role: 'admin',
        joined_at: new Date().toISOString(),
      });

    if (memberError) {
      console.error('Failed to add project creator as member:', memberError);
    }

    // Record metrics
    const monitoring = MonitoringService.getInstance();
    monitoring.recordMetric('projects.created', 1, {
      tenant_id: tenant.id,
      user_id: user?.id,
      status: input.status,
      priority: input.priority,
    });

    return project;
  },
});

// ============================================
// Project-Specific Routes (would be in [projectId]/route.ts)
// ============================================

/**
 * Example: GET /api/tenants/[tenantId]/projects/[projectId] - Get project
 */
export const getProject = createTenantHandler({
  requireOwnership: {
    table: 'projects',
    resourceIdParam: 'projectId',
    tenantIdColumn: 'tenant_id',
    selectColumns: `
      id,
      name,
      description,
      status,
      priority,
      tags,
      created_at,
      updated_at,
      created_by,
      updated_by,
      tenant_id
    `,
  },
  cache: {
    ttl: 600, // 10 minutes
  },
  handler: async ({ resource, tenant, supabase }) => {
    // Get project members
    const { data: members, error: membersError } = await supabase
      .from('project_members')
      .select(`
        user_id,
        role,
        joined_at,
        users(id, name, email)
      `)
      .eq('project_id', resource.id);

    if (membersError) throw membersError;

    // Get project statistics
    const { data: stats, error: statsError } = await supabase
      .from('tasks')
      .select('status', { count: 'exact' })
      .eq('project_id', resource.id);

    if (statsError) throw statsError;

    const taskStats = stats.reduce((acc, task) => {
      acc[task.status] = (acc[task.status] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      ...resource,
      members,
      statistics: {
        totalTasks: stats.length,
        ...taskStats,
      },
    };
  },
});

/**
 * Example: PUT /api/tenants/[tenantId]/projects/[projectId] - Update project
 */
export const updateProject = createTenantHandler({
  schema: UpdateProjectSchema,
  requireOwnership: {
    table: 'projects',
    resourceIdParam: 'projectId',
    tenantIdColumn: 'tenant_id',
    selectColumns: 'id, name, status, priority, updated_at',
  },
  handler: async ({ input, tenant, user, supabase, params }) => {
    const projectId = params.projectId;

    // Check if user has permission to update this project
    const { data: membership, error: memberError } = await supabase
      .from('project_members')
      .select('role')
      .eq('project_id', projectId)
      .eq('user_id', user?.id)
      .single();

    if (memberError || !membership) {
      throw new Error('Access denied: Not a project member');
    }

    if (!['admin', 'editor'].includes(membership.role)) {
      throw new Error('Access denied: Insufficient project permissions');
    }

    const { data, error } = await supabase
      .from('projects')
      .update({
        ...input,
        updated_at: new Date().toISOString(),
        updated_by: user?.id,
      })
      .eq('id', projectId)
      .eq('tenant_id', tenant.id)
      .select()
      .single();

    if (error) throw error;

    // Record metrics
    const monitoring = MonitoringService.getInstance();
    monitoring.recordMetric('projects.updated', 1, {
      tenant_id: tenant.id,
      user_id: user?.id,
      project_id: projectId,
    });

    return data;
  },
});

/**
 * Example: DELETE /api/tenants/[tenantId]/projects/[projectId] - Delete project
 */
export const deleteProject = createTenantHandler({
  requireOwnership: {
    table: 'projects',
    resourceIdParam: 'projectId',
    tenantIdColumn: 'tenant_id',
    selectColumns: 'id, name',
  },
  handler: async ({ tenant, user, supabase, params }) => {
    const projectId = params.projectId;

    // Check if user is project admin
    const { data: membership, error: memberError } = await supabase
      .from('project_members')
      .select('role')
      .eq('project_id', projectId)
      .eq('user_id', user?.id)
      .single();

    if (memberError || !membership || membership.role !== 'admin') {
      throw new Error('Access denied: Only project admins can delete projects');
    }

    // Soft delete by archiving
    const { error } = await supabase
      .from('projects')
      .update({
        status: 'archived',
        updated_at: new Date().toISOString(),
        updated_by: user?.id,
      })
      .eq('id', projectId)
      .eq('tenant_id', tenant.id);

    if (error) throw error;

    // Record metrics
    const monitoring = MonitoringService.getInstance();
    monitoring.recordMetric('projects.deleted', 1, {
      tenant_id: tenant.id,
      user_id: user?.id,
      project_id: projectId,
    });

    return { message: 'Project archived successfully' };
  },
});

// ============================================
// Cross-Tenant Operations (Admin Only)
// ============================================

/**
 * Example: POST /api/admin/tenants/[tenantId]/projects/migrate
 * Migrate projects between tenants (admin only)
 */
export const migrateProjects = createAuthenticatedHandler({
  allowedRoles: ['super_admin'],
  schema: z.object({
    sourceTenantId: z.string(),
    targetTenantId: z.string(),
    projectIds: z.array(z.string()),
  }),
  handler: async ({ input, supabase }) => {
    const { sourceTenantId, targetTenantId, projectIds } = input;

    // Verify both tenants exist
    const tenantManager = TenantManager.getInstance();
    const sourceTenant = await tenantManager.getTenant(sourceTenantId);
    const targetTenant = await tenantManager.getTenant(targetTenantId);

    if (!sourceTenant || !targetTenant) {
      throw new Error('Invalid source or target tenant');
    }

    // Migrate projects
    const { data, error } = await supabase
      .from('projects')
      .update({
        tenant_id: targetTenantId,
        updated_at: new Date().toISOString(),
      })
      .in('id', projectIds)
      .eq('tenant_id', sourceTenantId)
      .select();

    if (error) throw error;

    // Record migration metrics
    const monitoring = MonitoringService.getInstance();
    monitoring.recordMetric('projects.migrated', data.length, {
      source_tenant: sourceTenantId,
      target_tenant: targetTenantId,
    });

    return {
      migrated: data.length,
      projects: data,
    };
  },
});

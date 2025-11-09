/**
 * Basic API Example - User Management
 *
 * This example demonstrates basic CRUD operations with authentication,
 * validation, and sanitization.
 */

import { z } from 'zod';
import {
  createHandler,
  createAuthenticatedHandler,
  createAdminHandler
} from '../../../../src';

// Validation schemas
const CreateUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100),
  role: z.enum(['user', 'admin']).default('user'),
});

const UpdateUserSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  email: z.string().email().optional(),
  role: z.enum(['user', 'admin']).optional(),
});

// ============================================
// Public Routes
// ============================================

/**
 * GET /api/users - List users (public, but filtered)
 */
export const GET = createHandler({
  schema: z.object({
    limit: z.number().min(1).max(100).default(10),
    offset: z.number().min(0).default(0),
    search: z.string().optional(),
  }),
  cache: {
    ttl: 300, // 5 minutes
    keyGenerator: (req) => {
      const searchParams = req.nextUrl.searchParams;
      return `users:list:${searchParams.get('limit')}:${searchParams.get('offset')}:${searchParams.get('search') || ''}`;
    },
  },
  handler: async ({ input, supabase }) => {
    const { limit, offset, search } = input;

    let query = supabase
      .from('users')
      .select('id, name, email, role, created_at')
      .range(offset, offset + limit - 1);

    if (search) {
      query = query.or(`name.ilike.%${search}%,email.ilike.%${search}%`);
    }

    const { data, error, count } = await query;

    if (error) throw error;

    return {
      users: data,
      pagination: {
        limit,
        offset,
        total: count,
        hasMore: offset + limit < (count || 0),
      },
    };
  },
});

// ============================================
// Authenticated Routes
// ============================================

/**
 * POST /api/users - Create user (authenticated)
 */
export const POST = createAuthenticatedHandler({
  schema: CreateUserSchema,
  allowedRoles: ['admin'], // Only admins can create users
  rateLimit: {
    windowMs: 60000, // 1 minute
    maxRequests: 10, // 10 user creations per minute
  },
  handler: async ({ input, user, supabase }) => {
    // Check if email already exists
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', input.email)
      .single();

    if (existingUser) {
      throw new Error('User with this email already exists');
    }

    const { data, error } = await supabase
      .from('users')
      .insert({
        ...input,
        created_by: user.id,
      })
      .select()
      .single();

    if (error) throw error;

    return data;
  },
});

// ============================================
// User-Specific Routes (would be in [id]/route.ts)
// ============================================

/**
 * Example: GET /api/users/[id] - Get user by ID
 */
export const getUserById = createHandler({
  requireAuth: true,
  requireOwnership: {
    table: 'users',
    resourceIdParam: 'id',
    selectColumns: 'id, name, email, role, created_at',
  },
  cache: {
    ttl: 600, // 10 minutes for user data
  },
  handler: async ({ resource }) => {
    return resource;
  },
});

/**
 * Example: PUT /api/users/[id] - Update user
 */
export const updateUser = createAuthenticatedHandler({
  schema: UpdateUserSchema,
  requireOwnership: {
    table: 'users',
    resourceIdParam: 'id',
    selectColumns: 'id, name, email, role',
  },
  handler: async ({ input, supabase, params, user }) => {
    const userId = params.id;

    // Users can update themselves, admins can update anyone
    const canUpdate = user.id === userId || user.role === 'admin';
    if (!canUpdate) {
      throw new Error('Insufficient permissions');
    }

    const { data, error } = await supabase
      .from('users')
      .update({
        ...input,
        updated_at: new Date().toISOString(),
        updated_by: user.id,
      })
      .eq('id', userId)
      .select()
      .single();

    if (error) throw error;

    return data;
  },
});

/**
 * Example: DELETE /api/users/[id] - Delete user (admin only)
 */
export const deleteUser = createAdminHandler({
  requireOwnership: {
    table: 'users',
    resourceIdParam: 'id',
    selectColumns: 'id, name, email',
  },
  handler: async ({ supabase, params }) => {
    const userId = params.id;

    const { error } = await supabase
      .from('users')
      .delete()
      .eq('id', userId);

    if (error) throw error;

    return { message: 'User deleted successfully' };
  },
});

// ============================================
// Admin Routes
// ============================================

/**
 * Example: POST /api/users/bulk - Bulk operations (admin only)
 */
export const bulkCreateUsers = createAdminHandler({
  schema: z.object({
    users: z.array(CreateUserSchema).min(1).max(100),
  }),
  rateLimit: {
    windowMs: 300000, // 5 minutes
    maxRequests: 5, // 5 bulk operations per 5 minutes
  },
  handler: async ({ input, user, supabase }) => {
    const usersToCreate = input.users.map(userData => ({
      ...userData,
      created_by: user.id,
    }));

    const { data, error } = await supabase
      .from('users')
      .insert(usersToCreate)
      .select();

    if (error) throw error;

    return {
      created: data.length,
      users: data,
    };
  },
});

/**
 * Basic API Example - User Management
 *
 * This example demonstrates basic CRUD operations with authentication,
 * validation, and sanitization using Express + Prisma.
 */

import { Router } from 'express';
import { z } from 'zod';
import {
  createHandler,
  createAuthenticatedHandler,
  createAdminHandler
} from '../../../../src';

const router = Router();

// Validation schemas
const CreateUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100),
  role: z.enum(['USER', 'ADMIN']).default('USER'),
});

const UpdateUserSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  email: z.string().email().optional(),
  role: z.enum(['USER', 'ADMIN']).optional(),
});

// ============================================
// Public Routes
// ============================================

/**
 * GET /api/users - List users (public, but filtered)
 */
router.get('/', createHandler({
  schema: z.object({
    limit: z.number().min(1).max(100).default(10),
    offset: z.number().min(0).default(0),
    search: z.string().optional(),
  }),
  cache: {
    ttl: 300, // 5 minutes
    keyGenerator: (req) => {
      const query = req.query;
      return `users:list:${query.limit}:${query.offset}:${query.search || ''}`;
    },
  },
  handler: async ({ input, prisma }) => {
    const { limit, offset, search } = input;

    const whereClause: any = {};
    if (search) {
      whereClause.OR = [
        { name: { contains: search, mode: 'insensitive' } },
        { email: { contains: search, mode: 'insensitive' } },
      ];
    }

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where: whereClause,
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          createdAt: true,
        },
        skip: offset,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      prisma.user.count({ where: whereClause }),
    ]);

    return {
      users,
      pagination: {
        limit,
        offset,
        total,
        hasMore: offset + limit < total,
      },
    };
  },
}));

// ============================================
// Authenticated Routes
// ============================================

/**
 * POST /api/users - Create user (authenticated)
 */
router.post('/', createAuthenticatedHandler({
  schema: CreateUserSchema,
  allowedRoles: ['ADMIN'], // Only admins can create users
  rateLimit: {
    windowMs: 60000, // 1 minute
    maxRequests: 10, // 10 user creations per minute
  },
  handler: async ({ input, user, prisma }) => {
    // Check if email already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: input.email },
    });

    if (existingUser) {
      throw new Error('User with this email already exists');
    }

    const newUser = await prisma.user.create({
      data: {
        ...input,
        // Note: In real app, hash the password
        password: 'hashed-password-placeholder',
      },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        createdAt: true,
      },
    });

    return newUser;
  },
}));

// ============================================
// User-Specific Routes
// ============================================

/**
 * GET /api/users/:id - Get user by ID
 */
router.get('/:id', createAuthenticatedHandler({
  requireOwnership: {
    model: 'User',
    resourceIdParam: 'id',
    selectFields: ['id', 'name', 'email', 'role', 'createdAt'],
  },
  cache: {
    ttl: 600, // 10 minutes for user data
  },
  handler: async ({ resource }) => {
    return resource;
  },
}));

/**
 * PUT /api/users/:id - Update user
 */
router.put('/:id', createAuthenticatedHandler({
  schema: UpdateUserSchema,
  requireOwnership: {
    model: 'User',
    resourceIdParam: 'id',
    selectFields: ['id', 'name', 'email', 'role'],
  },
  handler: async ({ input, prisma, params, user }) => {
    const userId = params.id;

    // Users can update themselves, admins can update anyone
    const canUpdate = user?.id === userId || user?.role === 'ADMIN';
    if (!canUpdate) {
      throw new Error('Insufficient permissions');
    }

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: input,
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        updatedAt: true,
      },
    });

    return updatedUser;
  },
}));

/**
 * DELETE /api/users/:id - Delete user (admin only)
 */
router.delete('/:id', createAdminHandler({
  requireOwnership: {
    model: 'User',
    resourceIdParam: 'id',
    selectFields: ['id', 'name', 'email'],
  },
  handler: async ({ prisma, params }) => {
    const userId = params.id;

    await prisma.user.delete({
      where: { id: userId },
    });

    return { message: 'User deleted successfully' };
  },
}));

// ============================================
// Admin Routes
// ============================================

/**
 * POST /api/users/bulk - Bulk operations (admin only)
 */
router.post('/bulk', createAdminHandler({
  schema: z.object({
    users: z.array(CreateUserSchema).min(1).max(100),
  }),
  rateLimit: {
    windowMs: 300000, // 5 minutes
    maxRequests: 5, // 5 bulk operations per 5 minutes
  },
  handler: async ({ input, user, prisma }) => {
    const usersToCreate = input.users.map(userData => ({
      ...userData,
      // Note: In real app, hash the password
      password: 'hashed-password-placeholder',
    }));

    const createdUsers = await prisma.user.createMany({
      data: usersToCreate,
      skipDuplicates: true,
    });

    return {
      created: createdUsers.count,
      message: `${createdUsers.count} users created successfully`,
    };
  },
}));

export default router;

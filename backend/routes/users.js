const express = require('express')
const router = express.Router()
const {
  getUsers,
  getUser,
  updateUser,
  deleteUser,
  getUserStats,
  forceLogoutUser,
} = require('../controllers/userController')
const { protect, restrictTo } = require('../middleware/auth')
const { validateObjectId } = require('../middleware/validate')

router.use(protect, restrictTo('admin'))


/**
 * @openapi
 * /users/stats:
 *   get:
 *     tags:
 *       - Users
 *     summary: Get user statistics and role counts (Admin only)
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: User statistics retrieved
 */
router.get('/stats', getUserStats)

/**
 * @openapi
 * /users:
 *   get:
 *     tags:
 *       - Users
 *     summary: Get all system users (Admin only)
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: List of users
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/User'
 */
router.route('/').get(getUsers)

/**
 * @openapi
 * /users/{id}:
 *   get:
 *     tags:
 *       - Users
 *     summary: Get single user by ID (Admin only)
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User details retrieved
 *       404:
 *         description: User not found
 *   put:
 *     tags:
 *       - Users
 *     summary: Update user profile and roles (Admin only)
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User updated
 *   delete:
 *     tags:
 *       - Users
 *     summary: Delete user account (Admin only)
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User deleted
 */
router
  .route('/:id')
  .get(validateObjectId, getUser)
  .put(validateObjectId, updateUser)
  .delete(validateObjectId, deleteUser)

router.post('/:id/force-logout', validateObjectId, forceLogoutUser)

module.exports = router


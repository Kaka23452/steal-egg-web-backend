/* =========================================================
   ADMIN: RESET BUYER PASSWORD
   Requires an authenticated admin session.
========================================================= */

app.post(
  '/api/admin/users/:id/reset-password',
  requireAdmin,
  async (req, res) => {
    if (!needDb(res)) {
      return;
    }

    const userId = Number(req.params.id);
    const newPassword = str(req.body?.password);

    if (!Number.isSafeInteger(userId) || userId < 1) {
      return sendError(res, 400, 'Invalid buyer ID');
    }

    if (newPassword.length < 8 || newPassword.length > 128) {
      return sendError(
        res,
        400,
        'Password must be between 8 and 128 characters'
      );
    }

    try {
      const [users] = await pool.execute(
        'SELECT id FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      if (!users.length) {
        return sendError(res, 404, 'Buyer not found');
      }

      const passwordHash = await bcrypt.hash(newPassword, 12);

      await pool.execute(
        `UPDATE users
         SET password_hash = ?,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [passwordHash, userId]
      );

      return res.json({
        success: true,
        message: 'Buyer password reset successfully'
      });
    } catch (error) {
      console.error(
        '[reset buyer password]',
        error.message || error
      );

      return sendError(
        res,
        500,
        'Could not reset buyer password'
      );
    }
  }
);

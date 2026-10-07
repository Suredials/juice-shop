/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      res.status(401).json({ error: 'Authentication required' })
      return
    }
    if (req.body.imageUrl !== undefined) {
      let imageUrl: URL
      try {
        if (typeof req.body.imageUrl !== 'string' || req.body.imageUrl.length > 2048) throw new Error('Invalid image URL')
        imageUrl = new URL(req.body.imageUrl)
        if (!['https:', 'http:'].includes(imageUrl.protocol) || imageUrl.username || imageUrl.password) throw new Error('Invalid image URL')
      } catch {
        res.status(400).json({ error: 'Invalid image URL' })
        return
      }
      try {
        const user = await UserModel.findByPk(loggedInUser.data.id)
        if (!user) {
          res.status(404).json({ error: 'User not found' })
          return
        }
        await user.update({ profileImage: imageUrl.href })
      } catch (error) {
        next(error)
        return
      }
    }
    res.redirect((process.env.BASE_PATH ?? '') + '/profile')
  }
}

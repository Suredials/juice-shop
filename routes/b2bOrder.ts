/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    try {
      if (typeof body.orderLinesData !== 'string' || body.orderLinesData.length > 65536) {
        res.status(400).json({ error: 'Invalid order data' })
        return
      }
      const lines: unknown = JSON.parse(body.orderLinesData)
      if (lines === null || typeof lines !== 'object' || (Array.isArray(lines) && lines.length > 1000)) {
        res.status(400).json({ error: 'Order lines must be a JSON object or array' })
        return
      }
    } catch {
      res.status(400).json({ error: 'Order data must be JSON' })
      return
    }
    res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}

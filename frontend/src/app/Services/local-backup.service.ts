/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Injectable, inject } from '@angular/core'
import { type Backup } from '../Models/backup.model'

import { SnackBarHelperService } from './snack-bar-helper.service'
import { MatSnackBar } from '@angular/material/snack-bar'
import { firstValueFrom, forkJoin, from, of } from 'rxjs'
import { ChallengeService } from './challenge.service'

@Injectable({
  providedIn: 'root'
})
export class LocalBackupService {
  private readonly challengeService = inject(ChallengeService)
  private readonly snackBarHelperService = inject(SnackBarHelperService)
  private readonly snackBar = inject(MatSnackBar)

  private readonly VERSION = 1

  async save (fileName = 'owasp_juice_shop'): Promise<void> {
    const backup: Backup = { version: this.VERSION }

    backup.banners = {
      welcomeBannerStatus: this.getCookie('welcomebanner_status') || undefined,
      cookieConsentStatus: this.getCookie('cookieconsent_status') || undefined
    }
    backup.language = this.getCookie('language') || undefined

    try {
      const [continueCode, continueCodeFindIt, continueCodeFixIt] = await firstValueFrom(forkJoin([
        this.challengeService.continueCode(),
        this.challengeService.continueCodeFindIt(),
        this.challengeService.continueCodeFixIt()
      ]))
      backup.continueCode = continueCode
      backup.continueCodeFindIt = continueCodeFindIt
      backup.continueCodeFixIt = continueCodeFixIt
    } catch {
      console.log('Failed to retrieve continue code(s) for backup from server. Using cookie values as fallback.')
      backup.continueCode = this.getCookie('continueCode') || undefined
      backup.continueCodeFindIt = this.getCookie('continueCodeFindIt') || undefined
      backup.continueCodeFixIt = this.getCookie('continueCodeFixIt') || undefined
    }

    const blob = new Blob([JSON.stringify(backup)], { type: 'text/plain;charset=utf-8' })
    this.saveFile(blob, `${fileName}-${new Date().toISOString().split('T')[0]}.json`)
  }

  saveFile (blob: Blob, fileName: string) {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = fileName
    a.click()
    URL.revokeObjectURL(url)
  }

  restore (backupFile: File) {
    return from(backupFile.text().then((backupData) => {
      const backup: Backup = JSON.parse(backupData)

      if (backup.version === this.VERSION) {
        this.restoreCookie('welcomebanner_status', backup.banners?.welcomeBannerStatus)
        this.restoreCookie('cookieconsent_status', backup.banners?.cookieConsentStatus)
        this.restoreCookie('language', backup.language)
        this.restoreCookie('continueCodeFindIt', backup.continueCodeFindIt)
        this.restoreCookie('continueCodeFixIt', backup.continueCodeFixIt)
        this.restoreCookie('continueCode', backup.continueCode)

        const snackBarRef = this.snackBar.open('Backup has been restored from ' + backupFile.name, 'Apply changes now', {
          duration: 10000,
          panelClass: ['mat-body']
        })
        snackBarRef.onAction().subscribe(() => {
          const hackingProgress = backup.continueCode ? this.challengeService.restoreProgress(encodeURIComponent(backup.continueCode)) : of(true)
          const findItProgress = backup.continueCodeFindIt ? this.challengeService.restoreProgressFindIt(encodeURIComponent(backup.continueCodeFindIt)) : of(true)
          const fixItProgress = backup.continueCodeFixIt ? this.challengeService.restoreProgressFixIt(encodeURIComponent(backup.continueCodeFixIt)) : of(true)
          forkJoin([hackingProgress, findItProgress, fixItProgress]).subscribe({
            next: () => {
              location.reload()
            },
            error: (err) => { console.log(err) }
          })
        })
      } else {
        this.snackBarHelperService.open(`Version ${backup.version} is incompatible with expected version ${this.VERSION}`, 'errorBar')
      }
    }).catch((err: Error) => {
      this.snackBarHelperService.open(`Backup restore operation failed: ${err.message}`, 'errorBar')
    }))
  }

  private restoreCookie (cookieName: string, cookieValue: string) {
    if (cookieValue) {
      const expires = new Date()
      expires.setFullYear(expires.getFullYear() + 1)
      document.cookie = `${encodeURIComponent(cookieName)}=${encodeURIComponent(cookieValue)}; expires=${expires.toUTCString()}; path=/; SameSite=Lax`
    } else {
      document.cookie = `${encodeURIComponent(cookieName)}=; Max-Age=0; path=/; SameSite=Lax`
    }
  }

  private getCookie (cookieName: string): string | undefined {
    const prefix = `${encodeURIComponent(cookieName)}=`
    const cookie = document.cookie.split(';').map((entry) => entry.trim()).find((entry) => entry.startsWith(prefix))

    if (!cookie) {
      return undefined
    }

    const value = cookie.slice(prefix.length)

    try {
      return decodeURIComponent(value)
    } catch {
      return value
    }
  }
}

import { computed, toValue } from 'vue'
import { t } from '../i18n/index.js'
import { useDaemonStream } from './useDaemonStream.js'

export function useProfileActivity(profile) {
  const stream = useDaemonStream()
  const daemonState = computed(() => stream.daemonStatus?.profiles?.find((item) => item.name === toValue(profile)))
  const runningJob = computed(() => stream.jobs.some((job) => job.profile === toValue(profile) && job.state === 'running'))
  const externalBusy = computed(() =>
    Boolean(daemonState.value?.busy) &&
    daemonState.value?.state !== 'running_sync' &&
    !runningJob.value
  )
  const serverBusy = computed(() =>
    Boolean(daemonState.value?.busy) ||
    daemonState.value?.state === 'running_sync' ||
    runningJob.value
  )
  const blockedReason = computed(() => {
    if (daemonState.value?.state === 'running_sync' || daemonState.value?.active_operation === 'sync') {
      return t('workspace.syncInProgress')
    }
    if (runningJob.value) return t('workspace.jobInProgress')
    if (externalBusy.value) {
      return daemonState.value?.active_operation === 'external'
        ? t('workspace.externalProcessInProgress')
        : t('workspace.jobInProgress')
    }
    return ''
  })

  return { serverBusy, runningJob, externalBusy, blockedReason }
}

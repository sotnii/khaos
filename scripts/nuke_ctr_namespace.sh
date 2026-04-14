#!/usr/bin/env bash
set -Eeuo pipefail

# Usage:
#   ./nuke-containerd-namespace.sh <namespace>

NS="${1:-}"
CTR_BIN="${CTR_BIN:-ctr}"

if [[ -z "$NS" ]]; then
  echo "Usage: $0 <namespace>" >&2
  exit 1
fi

log() {
  echo "[*] $*"
}

warn() {
  echo "[!] $*" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

namespace_exists() {
  $CTR_BIN namespaces list 2>/dev/null | awk 'NR>1 {print $1}' | grep -Fxq "$NS"
}

list_containers() {
  $CTR_BIN -n "$NS" containers list 2>/dev/null | awk 'NR>1 {print $1}'
}

list_tasks() {
  $CTR_BIN -n "$NS" tasks list 2>/dev/null | awk 'NR>1 {print $1}'
}

list_images() {
  $CTR_BIN -n "$NS" images list 2>/dev/null | awk 'NR>1 {print $1}'
}

list_leases() {
  $CTR_BIN -n "$NS" leases ls 2>/dev/null | awk 'NR>1 {print $1}'
}

list_snapshotters() {
  # Typical output columns:
  # TYPE ID PLATFORMS STATUS
  # io.containerd.snapshotter.v1 overlayfs linux/amd64 ok
  $CTR_BIN plugins ls 2>/dev/null | awk '$1 ~ /^io\.containerd\.snapshotter\.v1/ {print $2}'
}

list_snapshots() {
  local snapshotter="$1"
  $CTR_BIN -n "$NS" snapshots --snapshotter "$snapshotter" ls 2>/dev/null | awk 'NR>1 {print $1}'
}

list_content_digests() {
  $CTR_BIN -n "$NS" content ls 2>/dev/null | awk 'NR>1 {print $1}'
}

delete_tasks() {
  log "Deleting tasks in namespace: $NS"

  local tasks
  tasks="$(list_tasks || true)"

  if [[ -z "$tasks" ]]; then
    log "No tasks found"
    return
  fi

  while IFS= read -r task; do
    [[ -z "$task" ]] && continue
    log "Killing task: $task"
    $CTR_BIN -n "$NS" tasks kill -s SIGKILL "$task" 2>/dev/null || true

    log "Deleting task: $task"
    $CTR_BIN -n "$NS" tasks delete -f "$task" 2>/dev/null || true
  done <<< "$tasks"
}

delete_containers() {
  log "Deleting containers in namespace: $NS"

  local containers
  containers="$(list_containers || true)"

  if [[ -z "$containers" ]]; then
    log "No containers found"
    return
  fi

  while IFS= read -r c; do
    [[ -z "$c" ]] && continue
    log "Deleting container: $c"
    $CTR_BIN -n "$NS" containers delete "$c" 2>/dev/null || true
  done <<< "$containers"
}

delete_snapshots() {
  log "Deleting snapshots in namespace: $NS"

  local snapshotters
  snapshotters="$(list_snapshotters || true)"

  if [[ -z "$snapshotters" ]]; then
    warn "Could not discover snapshotters, trying overlayfs"
    snapshotters="overlayfs"
  fi

  while IFS= read -r snapshotter; do
    [[ -z "$snapshotter" ]] && continue
    log "Checking snapshotter: $snapshotter"

    local changed=1
    local pass=1

    while [[ "$changed" -eq 1 ]]; do
      changed=0
      local snapshots
      snapshots="$(list_snapshots "$snapshotter" || true)"

      if [[ -z "$snapshots" ]]; then
        break
      fi

      log "Snapshot delete pass $pass on $snapshotter"
      while IFS= read -r snap; do
        [[ -z "$snap" ]] && continue
        if $CTR_BIN -n "$NS" snapshots --snapshotter "$snapshotter" rm "$snap" >/dev/null 2>&1; then
          log "Deleted snapshot [$snapshotter]: $snap"
          changed=1
        fi
      done <<< "$snapshots"

      pass=$((pass + 1))
    done

    local remaining
    remaining="$(list_snapshots "$snapshotter" || true)"
    if [[ -n "$remaining" ]]; then
      warn "Some snapshots could not be removed in snapshotter '$snapshotter':"
      echo "$remaining" >&2
    else
      log "No snapshots remain in snapshotter: $snapshotter"
    fi
  done <<< "$snapshotters"
}

delete_images() {
  log "Deleting images in namespace: $NS"

  local images
  images="$(list_images || true)"

  if [[ -z "$images" ]]; then
    log "No images found"
    return
  fi

  while IFS= read -r img; do
    [[ -z "$img" ]] && continue
    log "Deleting image: $img"
    $CTR_BIN -n "$NS" images rm "$img" 2>/dev/null || true
  done <<< "$images"
}

delete_content() {
  log "Deleting content blobs in namespace: $NS"

  local digests
  digests="$(list_content_digests || true)"

  if [[ -z "$digests" ]]; then
    log "No content blobs found"
    return
  fi

  while IFS= read -r digest; do
    [[ -z "$digest" ]] && continue
    log "Deleting content blob: $digest"
    $CTR_BIN -n "$NS" content rm "$digest" 2>/dev/null || true
  done <<< "$digests"
}

delete_leases() {
  log "Deleting leases in namespace: $NS"

  if ! $CTR_BIN leases ls >/dev/null 2>&1; then
    log "Leases command not available; skipping"
    return
  fi

  local leases
  leases="$(list_leases || true)"

  if [[ -z "$leases" ]]; then
    log "No leases found"
    return
  fi

  while IFS= read -r lease; do
    [[ -z "$lease" ]] && continue
    log "Deleting lease: $lease"
    $CTR_BIN -n "$NS" leases delete "$lease" 2>/dev/null || true
  done <<< "$leases"
}

delete_namespace() {
  log "Deleting namespace: $NS"
  $CTR_BIN namespaces remove "$NS"
}

show_leftovers() {
  warn "Namespace still not empty. Remaining objects:"

  warn "Containers:"
  $CTR_BIN -n "$NS" containers list 2>/dev/null || true

  warn "Tasks:"
  $CTR_BIN -n "$NS" tasks list 2>/dev/null || true

  warn "Images:"
  $CTR_BIN -n "$NS" images list 2>/dev/null || true

  warn "Content:"
  $CTR_BIN -n "$NS" content ls 2>/dev/null || true

  local snapshotters
  snapshotters="$(list_snapshotters || true)"
  if [[ -z "$snapshotters" ]]; then
    snapshotters="overlayfs"
  fi

  while IFS= read -r snapshotter; do
    [[ -z "$snapshotter" ]] && continue
    warn "Snapshots ($snapshotter):"
    $CTR_BIN -n "$NS" snapshots --snapshotter "$snapshotter" ls 2>/dev/null || true
  done <<< "$snapshotters"

  warn "Leases:"
  $CTR_BIN -n "$NS" leases ls 2>/dev/null || true
}

main() {
  require_cmd "$CTR_BIN"

  if ! namespace_exists; then
    echo "Namespace '$NS' does not exist (try to run as root)" >&2
    exit 1
  fi

  log "NUKING containerd namespace: $NS"

  delete_tasks
  delete_containers
  delete_snapshots
  delete_images
  delete_content
  delete_leases

  if ! delete_namespace; then
    warn "Failed to delete namespace '$NS'"
    show_leftovers
    exit 1
  fi

  log "Namespace '$NS' deleted successfully"
}

main
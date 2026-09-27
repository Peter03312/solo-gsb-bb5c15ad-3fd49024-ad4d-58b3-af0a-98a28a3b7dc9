// 迁移执行编排：基于「现有登记」与静态租约批量导入的「无冲突合并快照」，
// 生成一份按顺序执行时不会产生瞬时重复 IPv4 的逐步改址清单。
//
// 关键不变量：
//   1. 只复用 leaseImport 的无冲突结果（canApply=true）；CSV 有冲突时本模块不产生任何步骤；
//   2. 模块纯只读：不修改规划与任何登记状态，CSV / 规划 / 登记变化后由调用方重新执行即可实时重算；
//   3. 以「旧地址占用关系」建立依赖：设备 X 的目标地址当前由设备 Y 占用，则 X 依赖 Y 先迁出；
//      无环（DAG）部分按「目标地址最低优先」的可执行顺序逐步输出；
//   4. 互换或多设备环路（依赖图中的环）先把环中一台设备迁到其【原网段】内最低的临时可用地址
//      （候选须排除全部当前占用与全部目标地址，亦排除此前为其他环路选定的临时地址），
//      再依次完成环路，最后把该设备从临时地址迁到目标地址并自然释放临时地址；
//      环中没有任何一台设备能在其原网段找到临时地址时，明确阻止该环（并阻止整个清单）；
//   5. 新建设备（CSV 中的新 MAC）在其目标地址腾空后才能上线；目标地址被不会迁走的
//      既有设备占住时，作为阻断项明确列出。

import { intToIp } from './ip'
import { allocatableSegments, type AllocSegment } from './hosts'
import type { HostAssignment, PlanResult } from './types'
import type { LeaseImportResult } from './leaseImport'

/* ---------- 结果模型 ---------- */

/** 单步操作类型 */
export type MigrationStepKind =
  | 'temp-move' // 环：某设备先迁到原网段内的临时可用地址
  | 'move' // 设备迁到目标地址（环中非锚点设备、以及 DAG 中的普通迁移）
  | 'cycle-complete' // 环：锚点设备从临时地址迁到目标地址，临时地址随之释放
  | 'add' // 新设备上线到目标地址

export const MIGRATION_STEP_LABEL: Record<MigrationStepKind, string> = {
  'temp-move': '临时迁出',
  move: '迁移',
  'cycle-complete': '完成环路',
  add: '新增上线',
}

export interface MigrationStep {
  /** 执行序号（从 1 开始） */
  order: number
  kind: MigrationStepKind
  /** 设备稳定登记 ID（新增设备为合并快照中生成的新 ID） */
  deviceId: string
  /** 设备名（目标快照中的名称） */
  name: string
  /** 迁移前地址（临时迁出 / 普通迁移步骤） */
  fromAddress?: number
  /** 目标地址；临时迁出步骤的目标即临时地址 */
  address: number
  /** 临时地址（仅环的锚点设备的步骤存在） */
  tempAddress?: number
  /** 目标网段（设备最终所属网段）CIDR */
  targetCidr: string
  /** 临时地址所在原网段 CIDR（临时迁出步骤） */
  tempCidr?: string
  /** 该步的原因说明 */
  reason: string
}

/** 阻止生成清单的问题（占用者不会迁走 / 环路无临时地址 / 上游预览尚未就绪） */
export interface MigrationBlocker {
  kind: 'occupied' | 'no-temp' | 'pending'
  /** 相关设备名（no-temp 时为环中全部设备名） */
  devices: string[]
  address?: number
  message: string
}

/** 环（依赖强连通分量）的描述，供面板展示依赖构成 */
export interface MigrationCycle {
  /** 环中设备 ID（按依赖顺序） */
  deviceIds: string[]
  deviceNames: string[]
  /** 被选为临时锚点的设备 ID（无法找到临时地址时为 undefined） */
  pivotId?: string
  pivotName?: string
  tempAddress?: number
  tempCidr?: string
  blocked: boolean
  blockReason?: string
}

export interface MigrationPlan {
  /** 是否成功生成完整清单（false 时 steps 不完整/为空，调用方不得复制为执行依据） */
  ok: boolean
  steps: MigrationStep[]
  blockers: MigrationBlocker[]
  cycles: MigrationCycle[]
  counts: {
    moves: number // 改址设备数（不含纯新增）
    adds: number // 纯新增设备数
    cycles: number // 环路数
    tempMoves: number // 临时迁出步数
  }
  /** 参与迁移（地址发生变化）的设备总数 */
  changedDevices: number
}

/* ---------- 内部模型 ---------- */

interface DeviceView {
  id: string
  name: string
  /** 目标地址（合并快照） */
  target: number
  targetCidr: string
  /** 旧地址：既有设备为其当前地址；新增设备为 undefined */
  from?: number
  /** 旧地址是否处于任何已分配网段的可用范围内（决定能否在「原网段」找临时地址） */
  fromSegment?: AllocSegment
  isNew: boolean
  /** 旧地址失效说明（不在网段 / 网络地址 / 广播地址等），仅用于阻断文案 */
  fromInvalidReason?: string
}

/* ---------- 主入口 ---------- */

/**
 * 依据无冲突的批量导入合并快照编排逐步改址清单。
 * 调用方须保证仅在 leaseImport.canApply 为 true 时调用（否则返回 ok=false 的阻断结果）。
 */
export function buildMigrationPlan(
  imported: LeaseImportResult,
  existing: HostAssignment[],
  result: PlanResult,
): MigrationPlan {
  if (!imported.canApply) {
    return {
      ok: false,
      steps: [],
      blockers: [
        {
          kind: 'pending',
          devices: [],
          message: 'CSV 预览仍存在冲突或尚无数据行：迁移编排不产生结果，且不会改动任何登记。',
        },
      ],
      cycles: [],
      counts: { moves: 0, adds: 0, cycles: 0, tempMoves: 0 },
      changedDevices: 0,
    }
  }

  const segs = allocatableSegments(result)
  const segByOwner = new Map<string, AllocSegment>()
  for (const seg of segs) segByOwner.set(seg.ownerId, seg)

  function segmentOfAddress(addr: number): AllocSegment | undefined {
    return segs.find((s) => addr >= s.start && addr <= s.end)
  }
  /** 仅当地址位于某网段【可用主机范围】内才算该网段的合法宿主（排除网络 / 广播地址） */
  function usableSegmentOfAddress(addr: number): AllocSegment | undefined {
    return segs.find((s) => addr > s.start && addr < s.end)
  }

  // 目标快照按 ID 索引
  const existingById = new Map<string, HostAssignment>()
  for (const a of existing) existingById.set(a.id, a)

  // 当前（迁移前）物理占用：地址 -> 占用该地址的全部既有设备 ID
  //（异常重复登记也纳入，任何同址目标都必须等这些设备全部离开）
  const occupants = new Map<number, Set<string>>()
  for (const a of existing) {
    let set = occupants.get(a.address)
    if (!set) {
      set = new Set()
      occupants.set(a.address, set)
    }
    set.add(a.id)
  }

  const allTargets = new Set<number>()
  const devices: DeviceView[] = []

  for (const target of imported.merged) {
    const old = existingById.get(target.id)
    const targetSeg = segByOwner.get(target.ownerId)
    if (!targetSeg) continue // 合并快照无冲突时不会发生（目标网段必为成功分配网段）
    const view: DeviceView = {
      id: target.id,
      name: target.name,
      target: target.address,
      targetCidr: targetSeg.cidr,
      isNew: !old,
    }
    if (old) {
      view.from = old.address
      if (old.address !== target.address) {
        const seg = segmentOfAddress(old.address)
        view.fromSegment = usableSegmentOfAddress(old.address)
        if (!view.fromSegment) {
          if (seg && old.address === seg.start) view.fromInvalidReason = `原地址 ${intToIp(old.address)} 是网段 ${seg.cidr} 的网络地址`
          else if (seg && old.address === seg.end) view.fromInvalidReason = `原地址 ${intToIp(old.address)} 是网段 ${seg.cidr} 的广播地址`
          else if (seg) view.fromInvalidReason = `原地址 ${intToIp(old.address)} 不在网段 ${seg.cidr} 的可用主机范围内`
          else view.fromInvalidReason = `原地址 ${intToIp(old.address)} 不属于当前任何成功分配网段`
        }
      }
    }
    devices.push(view)
  }

  allTargets.clear()
  for (const d of devices) allTargets.add(d.target)

  const blockers: MigrationBlocker[] = []

  // 改址设备与新建设备
  const movers = devices.filter((d) => !d.isNew && d.from !== undefined && d.from !== d.target)
  const adds = devices.filter((d) => d.isNew)
  const moverIds = new Set(movers.map((d) => d.id))

  /* ---------- 依赖边：目标地址当前被改址设备占用 ---------- */
  const deps = new Map<string, Set<string>>() // device -> 必须先迁出的设备
  for (const d of movers) {
    const set = new Set<string>()
    const occ = occupants.get(d.target)
    if (occ) {
      for (const id of occ) {
        if (id === d.id) continue
        if (moverIds.has(id)) set.add(id)
      }
    }
    deps.set(d.id, set)
  }

  /* ---------- 阻断项 1：目标地址被不会迁走的既有设备占住 ---------- */
  for (const d of devices) {
    if (d.isNew || (d.from !== undefined && d.from !== d.target)) {
      // 需要目标地址腾空的设备（新增 / 改址）
    } else {
      continue
    }
    const occ = occupants.get(d.target)
    if (!occ) continue
    for (const id of occ) {
      if (id === d.id) continue
      if (moverIds.has(id)) continue // 该占用者会迁走，形成依赖边
      const holder = existingById.get(id)?.name ?? '未命名设备'
      blockers.push({
        kind: 'occupied',
        devices: [holder],
        address: d.target,
        message: `设备“${d.name}”的目标地址 ${intToIp(d.target)} 被不会迁走的既有设备“${holder}”占用：请先在主机地址分配中为其改址或删除，再执行迁移。`,
      })
    }
  }

  /* ---------- 强连通分量（Tarjan，迭代式，仅改址设备参与） ---------- */
  const cycles = findCycles(movers, deps)

  /* ---------- 为每个环选取临时锚点与临时地址 ---------- */
  // 已被此前环路占用的临时地址：同样避让，保证各环步骤之间也不会瞬时撞址
  const usedTempAddresses = new Set<number>()
  const cycleViews: MigrationCycle[] = []
  // pivot -> { temp, tempSeg }
  const tempPlan = new Map<string, { temp: number; tempSeg: AllocSegment }>()

  // 环的展示顺序：按环中最小旧地址升序，保证确定性
  const cycleOrder = cycles
    .map((memberIds) => {
      const byId = new Map(movers.map((d) => [d.id, d]))
      const views = memberIds.map((id) => byId.get(id)!)
      const minFrom = Math.min(...views.map((d) => d.from!))
      return { memberIds, views, minFrom }
    })
    .sort((a, b) => a.minFrom - b.minFrom)

  for (const { memberIds, views } of cycleOrder) {
    const names = views.map((d) => d.name)
    // 锚点候选：环中「原网段」可用（旧地址在某网段可用范围内）的设备，
    // 按原地址升序、再按 ID 稳定排序
    const candidates = views
      .filter((d) => d.fromSegment)
      .sort((a, b) => (a.from! - b.from! || a.id < b.id ? -1 : a.id > b.id ? 1 : 0))

    let chosen: { device: DeviceView; temp: number; tempSeg: AllocSegment } | null = null
    const triedReasons: string[] = []
    for (const device of candidates) {
      const seg = device.fromSegment!
      const forbidden = new Set<number>([...allTargets, ...usedTempAddresses])
      // 该网段内全部当前占用都排除（环内设备、其他设备一视同仁）
      for (const addr of occupants.keys()) {
        if (addr > seg.start && addr < seg.end) forbidden.add(addr)
      }
      let found: number | null = null
      for (let addr = seg.start + 1; addr < seg.end; addr++) {
        if (!forbidden.has(addr)) {
          found = addr >>> 0
          break
        }
      }
      if (found !== null) {
        chosen = { device, temp: found, tempSeg: seg }
        break
      }
      triedReasons.push(
        `设备“${device.name}”的原网段 ${seg.cidr}（可用 ${seg.firstUsable} ~ ${seg.lastUsable}）内没有可排除全部当前占用与目标地址后的空闲地址`,
      )
    }

    if (!chosen) {
      const noValidSeg = views.filter((d) => !d.fromSegment)
      const detail =
        candidates.length === 0
          ? `环中设备都无法在其原网段内安排临时地址：${noValidSeg
              .map((d) => `“${d.name}”（${d.fromInvalidReason ?? '原网段不可用'}）`)
              .join('；')}`
          : triedReasons.join('；')
      const message =
        `地址依赖环（${names.map((n) => `“${n}”`).join(' → ')} 形成闭环）无法打破：${detail}。` +
        `已阻止该环，请先释放原网段内的一个可用主机地址（或调整 CSV 目标地址）后重试。`
      blockers.push({ kind: 'no-temp', devices: names, message })
      cycleViews.push({
        deviceIds: memberIds,
        deviceNames: names,
        blocked: true,
        blockReason: detail,
      })
      continue
    }

    usedTempAddresses.add(chosen.temp)
    tempPlan.set(chosen.device.id, { temp: chosen.temp, tempSeg: chosen.tempSeg })
    cycleViews.push({
      deviceIds: memberIds,
      deviceNames: names,
      pivotId: chosen.device.id,
      pivotName: chosen.device.name,
      tempAddress: chosen.temp,
      tempCidr: chosen.tempSeg.cidr,
      blocked: false,
    })
  }

  // 存在任何阻断项：不输出步骤（冲突预览式语义——不产生结果、不改动登记）
  if (blockers.length > 0) {
    return {
      ok: false,
      steps: [],
      blockers,
      cycles: cycleViews,
      counts: { moves: movers.length, adds: adds.length, cycles: cycles.length, tempMoves: 0 },
      changedDevices: movers.length + adds.length,
    }
  }

  /* ---------- 模拟执行，保证每一步都不会产生瞬时重复 IPv4 ---------- */
  const steps: MigrationStep[] = []
  const occupied = new Map<number, Set<string>>(
    [...occupants.entries()].map(([addr, set]) => [addr, new Set(set)]),
  )
  const pending = new Map<string, DeviceView>()
  for (const d of movers) pending.set(d.id, d)

  function removeOccupant(addr: number, id: string) {
    const set = occupied.get(addr)
    if (set) set.delete(id)
  }
  function addOccupant(addr: number, id: string) {
    let set = occupied.get(addr)
    if (!set) {
      set = new Set()
      occupied.set(addr, set)
    }
    set.add(id)
  }
  /** 目标地址当前已无「尚未完成迁移」的占用者（不含自身） */
  function targetFree(d: DeviceView): boolean {
    const set = occupied.get(d.target)
    if (!set) return true
    for (const id of set) if (id !== d.id) return false
    return true
  }

  let order = 1

  // 第 1 阶段：全部环锚点临时迁出（先在占用表中腾空其原地址）
  for (const cycle of cycleViews) {
    const pivotId = cycle.pivotId!
    const device = pending.get(pivotId)!
    const { temp, tempSeg } = tempPlan.get(pivotId)!
    removeOccupant(device.from!, device.id)
    addOccupant(temp, device.id)
    steps.push({
      order: order++,
      kind: 'temp-move',
      deviceId: device.id,
      name: device.name,
      fromAddress: device.from,
      address: temp,
      tempAddress: temp,
      targetCidr: device.targetCidr,
      tempCidr: tempSeg.cidr,
      reason: `设备“${device.name}”处于地址依赖环（${cycle.deviceNames.map((n) => `“${n}”`).join(' → ')}）中，先迁到原网段 ${tempSeg.cidr} 内最低的临时可用地址 ${intToIp(temp)}（已排除全部当前占用与目标地址），为环路腾空 ${intToIp(device.from!)}`,
    })
  }

  // 第 2 阶段：反复取目标地址最低、且目标已腾空的设备执行迁移，直至无环依赖全部完成、
  // 环内剩余设备也在锚点腾空后链式可执行
  while (pending.size > 0) {
    const ready = [...pending.values()].filter(targetFree).sort((a, b) =>
      a.target - b.target || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
    )
    if (ready.length === 0) {
      // 理论上不可达：所有环都已通过临时锚点打破；防御性阻断
      blockers.push({
        kind: 'no-temp',
        devices: [...pending.values()].map((d) => d.name),
        message: '仍存在无法排序的地址依赖环，迁移编排已中止。',
      })
      break
    }
    const d = ready[0]
    const isPivot = tempPlan.has(d.id)
    removeOccupant(currentAddressOf(d), d.id)
    addOccupant(d.target, d.id)
    pending.delete(d.id)
    if (isPivot) {
      const { temp } = tempPlan.get(d.id)!
      steps.push({
        order: order++,
        kind: 'cycle-complete',
        deviceId: d.id,
        name: d.name,
        fromAddress: temp,
        address: d.target,
        tempAddress: temp,
        targetCidr: d.targetCidr,
        reason: `环路已腾空：设备“${d.name}”从临时地址 ${intToIp(temp)} 迁到目标地址 ${intToIp(d.target)}（${d.targetCidr}），临时地址同步释放，环路完成`,
      })
    } else {
      const depNames = depNamesOf(d)
      steps.push({
        order: order++,
        kind: 'move',
        deviceId: d.id,
        name: d.name,
        fromAddress: d.from,
        address: d.target,
        targetCidr: d.targetCidr,
        reason:
          depNames.length > 0
            ? `目标地址 ${intToIp(d.target)} 的原占用设备 ${depNames.map((n) => `“${n}”`).join('、')} 已迁出，现可改址（${intToIp(d.from!)} → ${intToIp(d.target)}）`
            : `目标地址 ${intToIp(d.target)} 当前空闲，可直接改址（${intToIp(d.from!)} → ${intToIp(d.target)}），不产生瞬时重复`,
      })
    }
  }

  // 第 3 阶段：新建设备上线（目标地址此时必然已腾空，否则前面已作为阻断项拦截）
  for (const d of adds.sort((a, b) => a.target - b.target || (a.id < b.id ? -1 : 1))) {
    addOccupant(d.target, d.id)
    steps.push({
      order: order++,
      kind: 'add',
      deviceId: d.id,
      name: d.name,
      address: d.target,
      targetCidr: d.targetCidr,
      reason: `新设备“${d.name}”上线到目标地址 ${intToIp(d.target)}（${d.targetCidr}）；该地址已腾空，不会与任何在线设备重复`,
    })
  }

  if (blockers.length > 0) {
    return {
      ok: false,
      steps: [],
      blockers,
      cycles: cycleViews,
      counts: { moves: movers.length, adds: adds.length, cycles: cycles.length, tempMoves: tempPlan.size },
      changedDevices: movers.length + adds.length,
    }
  }

  return {
    ok: true,
    steps,
    blockers: [],
    cycles: cycleViews,
    counts: {
      moves: movers.length,
      adds: adds.length,
      cycles: cycles.length,
      tempMoves: tempPlan.size,
    },
    changedDevices: movers.length + adds.length,
  }

  /* --- 闭包工具：依赖于模拟执行中的占用状态，需在 occupied/pending 声明后使用 --- */
  function currentAddressOf(d: DeviceView): number {
    if (tempPlan.has(d.id)) return tempPlan.get(d.id)!.temp
    return d.from!
  }
  function depNamesOf(d: DeviceView): string[] {
    return [...(deps.get(d.id) ?? [])]
      .map((id) => existingById.get(id)?.name ?? '未命名设备')
      .sort()
  }
}

/* ---------- Tarjan 强连通分量（迭代实现，避免大环路递归溢出） ---------- */

function findCycles(movers: DeviceView[], deps: Map<string, Set<string>>): string[][] {
  const indexOf = new Map<string, number>()
  const low = new Map<string, number>()
  const onStack = new Set<string>()
  const stack: string[] = []
  let counter = 0
  const result: string[][] = []

  for (const start of movers) {
    if (indexOf.has(start.id)) continue
    // 迭代 DFS 帧：[节点, 下一条出边下标]
    const frames: Array<[string, number]> = [[start.id, 0]]
    indexOf.set(start.id, counter)
    low.set(start.id, counter)
    counter++
    stack.push(start.id)
    onStack.add(start.id)

    while (frames.length > 0) {
      const frame = frames[frames.length - 1]
      const [v, nextIdx] = frame
      const neighbors = [...(deps.get(v) ?? [])]
      if (nextIdx < neighbors.length) {
        frame[1] = nextIdx + 1
        const w = neighbors[nextIdx]
        if (!indexOf.has(w)) {
          indexOf.set(w, counter)
          low.set(w, counter)
          counter++
          stack.push(w)
          onStack.add(w)
          frames.push([w, 0])
        } else if (onStack.has(w)) {
          low.set(v, Math.min(low.get(v)!, indexOf.get(w)!))
        }
      } else {
        frames.pop()
        if (low.get(v) === indexOf.get(v)) {
          const component: string[] = []
          while (true) {
            const w = stack.pop()!
            onStack.delete(w)
            component.push(w)
            if (w === v) break
          }
          // 仅保留真正的环：分量内多于一台设备；自环（目标=原址）已在 movers 阶段排除
          if (component.length > 1) result.push(component)
        }
        if (frames.length > 0) {
          const parent = frames[frames.length - 1][0]
          low.set(parent, Math.min(low.get(parent)!, low.get(v)!))
        }
      }
    }
  }
  return result
}

/* ---------- 复制用纯文本清单 ---------- */

/** 生成适合复制粘贴的制表符分隔清单（每行：步骤、操作、设备、原地址、目标地址、临时地址、网段、原因） */
export function migrationPlanText(plan: MigrationPlan): string {
  if (!plan.ok || plan.steps.length === 0) return ''
  const header = ['步骤', '操作', '设备', '原地址', '目标地址', '临时地址', '目标网段', '原因'].join('\t')
  const lines = plan.steps.map((s) =>
    [
      String(s.order),
      MIGRATION_STEP_LABEL[s.kind],
      s.name,
      s.fromAddress !== undefined ? intToIp(s.fromAddress) : '—',
      intToIp(s.address),
      s.tempAddress !== undefined ? intToIp(s.tempAddress) : '—',
      s.targetCidr,
      s.reason,
    ].join('\t'),
  )
  lines.push(
    `\t完成\t—\t—\t—\t—\t—\t共 ${plan.steps.length} 步，按序执行期间任一地址都不会同时被两台设备占用（无瞬时重复 IPv4）`,
  )
  return [header, ...lines].join('\n')
}

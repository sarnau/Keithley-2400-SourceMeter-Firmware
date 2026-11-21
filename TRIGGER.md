# TRIGGER.md — Trigger model & arm/trigger state machine

Reverse-engineering notes on the Keithley 2400 **trigger model**: the two-layer
Arm/Trigger state machine, its event sources, the Source-Delay-Measure (SDM) step
chain, counts/delays, the Trigger Link I/O, `:INITiate`/`:ABORt`, and the operation-status
bits it drives. Companion to [MEASURE.md](MEASURE.md) (the A/D path the trigger model
drives) and the sweep notes in [SUMMARY.md](SUMMARY.md). All addresses are in the
Ghidra program `2400-FIRMWARE.bin` (firmware C34).

> Scope note: this documents the control/state layer. The per-point source and A/D
> work it invokes lives in [MEASURE.md](MEASURE.md); the sweep-point iteration it
> walks is in `SUMMARY.md` §Sweep Operation.

---

## 1. The two-layer model

SCPI defines a three-level model (Idle → **Arm layer** → **Trigger layer**), with the
Trigger layer running the **Source-Delay-Measure (SDM)** cycle once per point. The
firmware implements this with:

| Role | Symbol | Addr | Meaning |
|---|---|---|---|
| Overall run state | `gTriggerRunState` | `0x803812` | `0` = idle; non-zero = a sequence is running. A distinct value `5` is treated specially by the input-event handler (see §5). Written `0` by `main` at boot and by `TRIGGER_ABORT_TO_IDLE`. |
| Active layer index | `gTriggerActiveLayer` | `0x8018a8` | `0` = arm layer, `1` = trigger layer. Selects which per-layer state block (§2) the event handlers act on. |

`gTriggerRunState` is read all over the UI/command code (key handlers, `EXECUTE_COMMAND_B`,
`EXECUTE_COMMAND_QUERY`, menu edit) as the "is a trigger/sweep sequence in progress"
gate — e.g. front-panel keys and some commands behave differently while armed.

---

## 2. Per-layer state block (2 × 24-byte array @ `0x8027cc`)

Each layer keeps an identical 24-byte state record. The two records are a contiguous
array: **index 0 = Arm layer** (base address), **index 1 = Trigger layer** (base + 0x18).
The three stride forms seen in the decompiler (`[i*6]` for `long*`, `[i*0xc]` for `word*`,
`[i*0x18]` for `byte*`) all describe the same 24-byte element.

| Off | Addr (arm) | Symbol | Type | Proven meaning |
|---|---|---|---|---|
| +0  | `0x8027cc` | `gTrigLayerCountInit`   | long | Count reload value (`:ARM:COUNt` / `:TRIG:COUNt`). |
| +4  | `0x8027d0` | `gTrigLayerCount`       | long | Live down-counter for this layer. |
| +8  | `0x8027d4` | `gTrigLayerDelayReload` | long | Delay/timer reload. |
| +12 | `0x8027d8` | `gTrigLayerDelay`       | long | Live delay/timer value (`:TRIG:DELay`, `:ARM:TIMer`). |
| +16 | `0x8027dc` | `gSeqByte_dc_maybe`     | byte | Layer-local flag (role not fully proven). |
| +17 | `0x8027dd` | `gTrigLayerIsTimer`     | byte | `1` when source == `0x10` (TIMer); else `0`. |
| +18 | `0x8027de` | `gSeqByte_de_maybe`     | byte | Event-notify latch (set by `TRIGGER_LAYER_NOTIFY`). |
| +19 | `0x8027df` | `DAT_008027df`          | byte | Event-ack latch (set by `TRIGGER_EVENT_ACK_DISPATCH`). |
| +20 | `0x8027e0` | `gTrigLayerSource`      | word | Event-source bitmask for this layer (see §4). |
| +22 | `0x8027e2` | `gSeqFlag_e2_maybe`     | byte | Layer-enable flag (copied from layer-config +0x0F). |
| +23 | `0x8027e3` | `gTrigLayerImmediate`   | byte | `1` when source == `0x08` (IMMediate / auto-advance); else `0`. |

Remaining `_maybe` names are flagged where the exact role is not yet proven from code.

### Loading a layer — `TRIGGER_MODEL_SET_LAYER(layerIdx, cfgPtr)` @ `0x12782`

Copies a layer's configuration into the state block under IRQ mask:

```
src word @cfg+0x00  -> gTrigLayerSource[layer]          (and sets IsTimer / Immediate)
long    @cfg+0x02   -> gTrigLayerDelay / DelayReload[layer]
long    @cfg+0x06   -> gTrigLayerCount / CountInit[layer]
bool    @cfg+0x0F   -> gSeqFlag_e2_maybe[layer]
```

`CONFIGURE_MEASURE_FUNCTION` (@`0x17468`) calls it as:

```c
TRIGGER_MODEL_SET_LAYER(0, &gCONFIG_0x19E.ARM_SOURCE);      // arm layer
TRIGGER_MODEL_SET_LAYER(1, &gCONFIG_0x19E.TRIGGER_SOURCE);  // trigger layer
```

So the layer-config struct is the `ARM_*` / `TRIGGER_*` field group inside
`gCONFIG_0x19E` (see §6). Reset defaults observed: `ARM_SOURCE = 8` (IMM), arm count `1`;
`TRIGGER_SOURCE = 8` (IMM), trigger count `1`, delay `0`.

---

## 3. The SDM step chain — function-pointer slots

The trigger layer executes one **Source-Delay-Measure** cycle per point by walking a
chain of function pointers rather than a hard-coded sequence. Ten global slots hold the
step handlers; which handler lands in which slot is decided at configuration time by
**`TRIGGER_BUILD_MODEL_HANDLERS`** (@`0x12c7c`), based on pulse mode, sweep mode, and the
Trigger-Link input/output configuration.

### 3.1 The 10 step slots

| Slot global | Addr | Role (from `BUILD_MODEL_HANDLERS`) |
|---|---|---|
| `gTRIG_STEP_808560` | `0x808560` | **Trigger-layer entry step** — first step after a trigger event; selected by the output/input TLINk config switch (§3.3). |
| `gTRIG_STEP_805244` | `0x805244` | Source/pulse-delay start step. In pulse mode = `SOURCE_PULSE_DELAY_START`. |
| `gTRIG_STEP_805260` | `0x805260` | Trigger-block build step (pulse + memory-sweep path). |
| `gTRIG_STEP_801e6c` | `0x801e6c` | Point-setup step (source DAC / sweep-point / memory-point configure). |
| `gTRIG_STEP_801e68` | `0x801e68` | Secondary setup / OLINE-pulse step for arm-wait output modes. |
| `gTRIG_STEP_80393c` | `0x80393c` | Alternate point-setup step (memory-sweep branch). |
| `gTRIG_STEP_805524` | `0x805524` | Post-source-settle continuation (used by `TRIG_STEP_SELECT_SOURCE_DELAY`). |
| `gTRIG_STEP_801700` | `0x801700` | Step slot (sequence continuation). |
| `gTRIG_STEP_80461c` | `0x80461c` | Step slot (sequence continuation). |
| `gTRIG_STEP_8050e8` | `0x8050e8` | Step slot (sequence continuation). |

### 3.2 Step handler functions

The handlers assigned into the slots (and chained via `gCOMM_CALLBACK` / `gCOMM_CALLBACK_DONE`):

| Handler | Addr | What it does |
|---|---|---|
| `TRIG_STEP_SELECT_SOURCE_DELAY`        | `0xf53a` | Picks settle-vs-soak continuation; arms CH13 timer = `max(settle time, SOURCE1_DELAY)`. |
| `TRIG_STEP_OLINE_PULSE_THEN_DELAY`     | `0xf57e` | Pulse Trigger-Link output line, then delay. |
| `TRIG_STEP_OLINE_PULSE_THEN_FPTR`      | `0xf5aa` | Pulse OLINE, then call next slot. |
| `TRIG_STEP_OLINE_PULSE_THEN_ARM_WAIT`  | `0xf600` | Pulse OLINE, then wait for arm/trigger input. |
| `TRIG_STEP_OLINE_PULSE_THEN_SOAK`      | `0xf63e` | Pulse OLINE, then source soak. |
| `TRIG_STEP_CONTACT_CHECK_THEN_SOURCE_OFF` | `0xfb10` | Contact-check branch → source off. |
| `TRIG_STEP_CONTACT_CHECK_THEN_DISPATCH`   | `0xfb58` | Contact-check branch → dispatch next. |
| `TRIG_STEP_START_SETTLE_TIMER`         | `0xff5e` | Start source-settle timer. |
| `TRIGGER_SEQUENCE_SOURCE_OFF_STEP`     | `0xfacc` | Source-off sequence step. |
| `TRIGGER_SEQUENCE_OUTPUT_ON_STEP`      | `0xfba0` | Output-on sequence step. |

`BUILD_MODEL_HANDLERS` also references `OLINE_PULSE2` (double-pulse) variants and
`TRIGGER_ARM_INPUT_WAIT_E6C` / `_E68` / `TRIGGER_OUTPUT_PULSE_AND_ARM` for the
output-then-input-wait combinations.

### 3.3 Entry-step selection switch

`BUILD_MODEL_HANDLERS` computes a selector and chooses `gTRIG_STEP_808560`:

```c
bVar1 = gCONFIG_0x19E.TRIGGER_TCONFIGURE_OUTPUT & 3;
if (gCONFIG_0x19E.TRIGGER_SOURCE == 0x40)              // TLINk input
    bVar1 |= (gCONFIG_0x19E.TRIGGER_TCONFIGURE_INPUT & 6) << 1;
switch (bVar1) { ... }   // 0..0xc → entry step + OLINE-pulse combinations
```

i.e. the 2-bit **output**-trigger config (`TCONFIGURE_OUTPUT & 3`) combined, when the
source is TLINk (`0x40`), with the 2-bit **input**-trigger config selects whether the
entry step pulses the output line, waits for an input line, or both.

---

## 4. Event sources (`gTrigLayerSource` bitmask)

The source selection is a raw bitmask word per layer (no dedicated enum in the DB).
Proven bit values:

| Bit | Source | Where proven |
|---|---|---|
| `0x08` | **IMMediate** | reset default; sets `gTrigLayerImmediate` in `SET_LAYER`. |
| `0x10` | **TIMer** | sets `gTrigLayerIsTimer` in `SET_LAYER`. |
| `0x40` | **TLINk** (Trigger Link) | `BUILD_MODEL_HANDLERS` special-cases `TRIGGER_SOURCE == 0x40`, routing through `TCONFIGURE_INPUT`/`ILINE`. |
| `0x400` | **BUS** (`*TRG` / GPIB GET) | `TRIGGER_SEQUENCE_DISPATCH` tests `TRIGGER_SEQUENCE2_SOURCE & 0x400`; GPIB GET posts the `0x0404` marker (see [GPIB.md](GPIB.md)). |

The **arm layer** additionally supports MANual (TRIG key) and the start-of-test detectors
NSTest/PSTest/BSTest. `TRIGGER_INPUT_EVENT_HANDLER` masks the arm-layer source bits with
`0x382` (`0x200|0x100|0x80|0x02`) to distinguish those manual/detector sources from the
`0x40`-family TLINk sources; the exact bit→token split within `0x382` is not individually
pinned here.

---

## 5. Event handling & layer advance

| Function | Addr | Role |
|---|---|---|
| `TRIGGER_INPUT_EVENT_HANDLER` | `0x1267e` | Core event sink. `event 4` = TLINk-input arrived in the trigger layer (clears status bit 305, calls the pending step via `FUNCPTR_00805aa4`). Other events route per the active layer's source bits (`0x20` pending, `0x40` TLINk line, `0x382` arm detectors), disabling the relevant TPU input channel and trapping into the scheduler. |
| `TRIGGER_ARM_INPUT_OR_DISPATCH` | `0x12580` | If waiting on a TLINk input (`TCONFIGURE_INPUT & 1`): set `gTrigLinkInputPending`, raise status **305** (waiting in trigger layer), enable the `TCONFIGURE_ILINE` TPU input IRQ, stash the next step in `FUNCPTR_00805aa4`. Otherwise call `gTRIG_STEP_805244` directly. |
| `TRIGGER_EVENT_ACK_DISPATCH` | `0x12c2e` | Acknowledge an event for the active layer; for the trigger layer clears `gTrigLinkInputPending` + status 305 and jumps to the entry step `gTRIG_STEP_808560`. |
| `TRIGGER_LAYER_NOTIFY` | `0x12b32` | Post an event to the active layer (layer 1 → `TRIGGER_INPUT_EVENT_HANDLER(4)`; else latch `gSeqByte_de_maybe` and trap to the scheduler). |
| `TRIGGER_OUTPUT_PULSE_AND_ARM` | `0x1261e` | Toggle the `TRIGGER_TCONFIGURE_OLINE` output line, then enter the arm-input wait. |
| `MEASURE_TRIGGER_ONE` | `0x1288a` | Trigger a single measurement; optionally reset system time (`:SYST:TIME:RES:AUTO`) and trap to run it. |

`gTrigLinkInputPending` (`0x805628`) is the "armed, waiting for a Trigger-Link input
edge" flag.

### SDM measure-complete dispatch — `TRIGGER_SEQUENCE_DISPATCH` @ `0xfbec`

Runs when a point's A/D completes. It waits for the analog-comm block to drain
(`gTRANSMIT_BLOCK_DONE_FLAG`), then selects the next step into `gCOMM_CALLBACK_DONE`:

- **Contact-check mode** (`TRIGGER_SEQUENCE2_SOURCE & 0x400`): branch to
  `TRIG_STEP_CONTACT_CHECK_THEN_SOURCE_OFF` / `_THEN_DISPATCH`, or advance the sweep
  point (`SWEEP_POINT_PTR_ADVANCE`) → `OUTPUT_ON_SEQUENCE`, honoring `OUTPUT1_STATE` and
  `TRIGGER_SEQUENCE2_TOUT`.
- **Normal mode**: `OUTPUT_OFF_SEQUENCE` / `OUTPUT_ON_SEQUENCE` by the analog
  output-state bit (`TPU_Parameter_RAM[9][1] & 0x8000`), advancing the sweep pointer on
  the on-branch.

It then builds and transmits the next analog command block (`ANALOG_BUILD_BLOCK_CCS_SYS`
→ `COMM_TRANSMIT`). The post-measure continuation pointer `FUNCPTR_00805240` is set to
`MEASURE_STATE_MACHINE_DISPATCH` (normal) or `MEASURE_COMPLETE_SINGLE_READING` (pulse
mode) — see [MEASURE.md](MEASURE.md).

---

## 6. Configuration fields (`gCONFIG_0x19E`)

The persisted trigger config (see the CONFIG_0x19E field work) feeds `SET_LAYER`:

| Field | Off | Layer | Meaning |
|---|---|---|---|
| `ARM_SOURCE` | +152 | arm | `:ARM:SOURce` bitmask. |
| `ARM_TIMER` | +154 | arm | `:ARM:TIMer`. |
| `ARM_SEQUENCE1_LAYER1_COUNT` | +158 | arm | `:ARM:COUNt` (incl. INFinite). |
| `ARM_TCONFIGURE_ILINE/OLINE/INPUT/OUTPUT` | — | arm | Arm-layer Trigger-Link line + edge config. |
| `TRIGGER_SOURCE` | +174 | trig | `:TRIGger:SOURce` bitmask. |
| `TRIGGER_SEQUENCE1_COUNT` | +180 | trig | `:TRIGger:COUNt`. |
| `TRIGGER_SEQUENCE1_DELAY` | +184 | trig | `:TRIGger:DELay`. |
| `TRIGGER_TCONFIGURE_ILINE/OLINE/INPUT/OUTPUT` | — | trig | Trigger-layer Trigger-Link line + edge config (`:TRIG:ILIN/OLIN/INP/OUTP`). |
| `TRIGGER_SEQUENCE2_SOURCE` | — | trig | Contact-check / secondary sequence (`& 0x400` in dispatch). |
| `TRIGGER_SEQUENCE2_TOUT` | — | trig | Contact-check timeout branch. |
| `PulseModeEnable` | — | — | Selects pulse vs DC step chain in `BUILD_MODEL_HANDLERS`. |

---

## 7. Trigger Link hardware (TPU)

The Trigger Link lines are driven through the MC68332 **TPU** channels and digital I/O:

- **Output pulse:** `PORT_TOGGLE_BIT(TRIGGER_TCONFIGURE_OLINE)` — Meter-Complete / SDM
  output trigger on the configured output line.
- **Input edge IRQ:** `CPU_TPU_ANALOG_CHANNEL_ENABLE_IRQ(TRIGGER_TCONFIGURE_ILINE)` arms
  the input line; `..._DISABLE_IRQ` / `..._INITIALIZE` on event. Arm layer uses
  `ARM_TCONFIGURE_ILINE`.
- TPU channels referenced around the model: CH10, CH11, CH13 (delay/settle timer via
  `CPU_TPU_CH13_00006010`), CH14. See [BOOT.md](BOOT.md) for TPU init.

Physical: rear 8-pin micro-DIN, 4 TTL lines (factory: #2 out, #1 in), falling-edge input,
Meter-Complete output pulse (`SUMMARY.md` §Triggering).

---

## 8. Idle / INITiate / ABORt & operation-status bits

- **Idle → running:** `gTriggerRunState` is set when a sequence initiates (OUTPUT ON from
  the front panel, or `:INITiate` / `:READ?` / `:MEASure?` remote). `main` clears it to `0`
  at boot.
- **ABORt → idle:** `TRIGGER_ABORT_TO_IDLE` (@`0x128ce`) tears the model down: drains the
  comm block, clears `gTriggerRunState`, drops the ARM annunciator, disables the TPU
  input IRQs (CH11/CH13), clears the trigger/abort flags, reloads counters, and restores
  the measure dispatch pointer. Triggered by `:ABORt`, IFC/SDC/DCL, `:SYST:PRES`, `*RST`,
  `*RCL` (`SUMMARY.md`).

**Operation-status (condition register) bits** set/cleared via
`EventReg_ConditionReg_UpdateSet/Clear` (named in the `ERR_INDEX` enum):

| Bit | Enum token | STAT:OPER |
|---|---|---|
| +303 | `ERR_INDEX_303_DEVICE_SWEEPING` | B3 Swp — sweeping |
| +305 | `ERR_INDEX_305_WAITING_IN_TRIGGER_LAYER` | B5 Trig — waiting for trigger event |
| +306 | `ERR_INDEX_306_WAITING_IN_ARM_LAYER` | B6 Arm — waiting for arm event |
| +310 | `ERR_INDEX_310_RE-ENTERING_THE_IDLE_LAYER` | B10 Idle |

`TRIGGER_ABORT_TO_IDLE` clears 303/305/306 and sets 310; `ARM_INPUT_OR_DISPATCH` sets 305
while waiting on a Trigger-Link input.

---

## 9. Relationship to Sweep & Measure

- **Sweep:** when `gSWEEP_ACTIVE`, `BUILD_MODEL_HANDLERS` wires the point-setup slots to
  `SWEEP_POINT_SETUP_VSOURCE_PULSE` / `SWEEP_POINT_SETUP_ISOURCE` /
  `SWEEP_MEMORY_POINT_CONFIGURE` / `SWEEP_MEMORY_POINT_NEXT`; the dispatch step calls
  `SWEEP_POINT_PTR_ADVANCE`. The trigger count should equal (a multiple of) the sweep
  point count. Sweep globals: `gSweepPointCount` `0x813a5c`, `gSWEEP_POINT_INDEX`
  `0x8018d0`, `gSWEEP_ACTIVE` `0x8018d3`, `gSWEEP_DIRECTION` `0x8018d4`,
  `gSweepPointCounter_maybe` `0x8018d6`.
- **Measure (SDM):** the trigger model's step chain hands off to the A/D state machine
  (`MEASURE_STATE_MACHINE_DISPATCH`) once source + delay complete; the measure-complete
  callback (`TRIGGER_SEQUENCE_DISPATCH`) advances the point. The SDM timing budget is in
  `SUMMARY.md` Appendix A and [MEASURE.md](MEASURE.md).

---

## 10. Key symbols (quick reference)

**Dispatch / state machine:**
`TRIGGER_BUILD_MODEL_HANDLERS` `0x12c7c` · `TRIGGER_MODEL_SET_LAYER` `0x12782` ·
`TRIGGER_SEQUENCE_DISPATCH` `0xfbec` · `TRIGGER_ARM_INPUT_OR_DISPATCH` `0x12580` ·
`TRIGGER_INPUT_EVENT_HANDLER` `0x1267e` · `TRIGGER_EVENT_ACK_DISPATCH` `0x12c2e` ·
`TRIGGER_LAYER_NOTIFY` `0x12b32` · `TRIGGER_OUTPUT_PULSE_AND_ARM` `0x1261e` ·
`TRIGGER_ABORT_TO_IDLE` `0x128ce` · `MEASURE_TRIGGER_ONE` `0x1288a`.

**State vars:**
`gTriggerRunState` `0x803812` · `gTriggerActiveLayer` `0x8018a8` ·
`gTrigLinkInputPending` `0x805628` · per-layer block `0x8027cc` (arm) / `0x8027e4` (trig).

**Layer-block members (arm base):**
`gTrigLayerCountInit` `0x8027cc` · `gTrigLayerCount` `0x8027d0` ·
`gTrigLayerDelayReload` `0x8027d4` · `gTrigLayerDelay` `0x8027d8` ·
`gTrigLayerIsTimer` `0x8027dd` · `gTrigLayerSource` `0x8027e0` ·
`gTrigLayerImmediate` `0x8027e3`.

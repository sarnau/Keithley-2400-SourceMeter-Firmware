# MENU.md — Front-panel menu system & navigation

Reverse-engineering notes on the Keithley 2400 **front-panel menu system**: the menu tree,
the navigation state machine, key dispatch, the setup/trigger function model, menu text
rendering, numeric value editing, and how a confirmed change is persisted. Companion to
[DISPLAY.md](DISPLAY.md) (the VFD/key hardware pipeline), [CALIBRATION.md](CALIBRATION.md)
(the CAL submenu), and the config/EEPROM structures in `SUMMARY.md`. All addresses are in
`2400-FIRMWARE.bin` (firmware C34).

The key architectural fact: **the front-panel menu is a command generator.** Confirming a
menu item does not write config directly — it enqueues an internal command into the
front-panel command queue, processed by the *same* executor as remote GPIB/RS-232 SCPI
(§7). Front panel and bus share one control path.

---

## 1. Menu tree — `MENU_ITEM_STRUCT` (28 bytes)

| Off | Field | Meaning |
|---|---|---|
| +0  | `menuLines` (`MENU_TEXTS *`) | the 3 display strings for this item |
| +4  | `nextMenu` (`MENU_ITEM_STRUCT *`) | sibling / linked navigation target |
| +8  | `parentMenu` (`MENU_ITEM_STRUCT *`) | parent item (ascend on EXIT) |
| +12 | `itemType` (byte) | 0 = empty/placeholder, 1 = real menu |
| +13 | `selectCount1` (byte) | |
| +14 | `selectCount2` (byte) | |
| +16 | `menu` (`MENU_10_STRUCT *`) | **children**: array of up to 10 child items |
| +20 | `setupFunction` (`MENU_FN *`) | enter/display handler (called to render the item) |
| +24 | `triggerFunction` (`MENU_FN *`) | ENTER/act handler (called to apply the item) |

- **`MENU_TEXTS`** (12 B): `{char *title; char *line_left; char *line_right}` — the 2-line VFD
  content plus a title.
- **`MENU_10_STRUCT`** (40 B): `MENU_ITEM_STRUCT *menuItems[10]` — a submenu's child slots.

The hierarchy is built through the **`menu` field** (→ `MENU_10_STRUCT` of up to 10 children),
not the `nextMenu` sibling chain; `parentMenu` walks back up on EXIT.

### Top-level layout (root `MENU_ITEM_STRUCT_MAIN_MENU` @`0x652ac` → `MENU_10_STRUCT_00063c82`)

| Slot | Item | Title |
|---|---|---|
| 0 | `MENU_ITEM_SAVESETUP_MENU` | SAVESETUP MENU |
| 1 | `MENU_ITEM_COMMUNICATIONS_SETUP` | COMMUNICATIONS SETUP |
| 2 | `MENU_ITEM_CALIBRATION` | CALIBRATION |
| 3,4 | `MENU_ITEM_EMPTY` | (unused) |
| 5 | `MENU_ITEM_SELF_TEST_MENU` | SELF-TEST MENU |
| 6 | `MENU_ITEM_A/D_CONTROLS_a` | A/D CONTROLS |
| 7 | `MENU_ITEM_GENERAL_MENU` | GENERAL MENU |
| 8,9 | `MENU_ITEM_EMPTY` | (unused) |

(The many `MENU_ITEM_STRUCT_CONFIGURE_*` items — V/I-SOURCE, OUTPUT, TRIGGER, OHMS, LIMITS,
etc. @`0x65b00`–`0x666xx` — are the CONFIG-key submenus.)

---

## 2. Navigation state

| Symbol | Addr | Meaning |
|---|---|---|
| `gMenu_Current` | `0x807ede` | the current `MENU_ITEM_STRUCT *` |
| `gMenuCurrentSelectionIndex` | `0x807eee` | selected child slot (1..5, two banks of 5 via the window toggle) |
| `gMenuEnterSelected` | `0x8050f9` | ENTER-pressed flag (actions apply only when set) |
| `gMenuForUnit` | `0x807ee2` | per-measurement-function remembered menu position (array by unit) |
| `gMenu_Setup_Function` | `0x805624` | `MENU_FN *` — the current item's setup/display fn (dispatch slot) |
| `gMenuSetupPending` | `0x80855c` | menu redisplay/setup-dispatch pending (renamed from `gMenuCallFlag_maybe`) |
| `gMENU_STR_INDEX` | `0x805258` | editable-field index within a multi-field item (e.g. limit pattern digits) |

Tied to the display layer: `gDISPLAY_VIEW_MODE` and the display dirty flag drive
re-rendering (see [DISPLAY.md](DISPLAY.md)).

---

## 3. Navigation state machine

### Scheduler entry — `MENU_CALL_SETUP` @`0x3ceee`
Called from the boot scheduler loop. Each pass: process the FP command queue
(`FP_CMD_QUEUE_PROCESS`); if `gMenuSetupPending`, dispatch `(*gMenu_Setup_Function)()` to
render the current item; then read the next keycode (`KEY_GET_NEXT_KEYCODE_BY_MODE`), show
any pending error, and run the key handler (`KEY_EXECUTE_PRESS_FUNCTION`). So the loop is
**render current item → read key → dispatch key handler → apply**.

### Selection — `MENU_SELECT(target)` @`0x3faac` (41 callers)
The core navigator. It first calls the **current** item's `triggerFunction` (apply any
pending edit), checks value-range error flags, then resolves the next item: for a descend
into children it indexes `gMenu_Current->menu->menuItems[]` by `gMenuCurrentSelectionIndex`
(slots 0–4 or 5–9 depending on the display window bank), and sets
`gMenu_Current = MENU_MODIFY_BY_CONFIG(next)`. Helpers: `MENU_GET_PARENT` @`0x3f89a`
(ascend), `MENU_MODIFY_BY_CONFIG` @`0x3fd94` (substitute the config-appropriate variant),
`MENU_GET_NEXT_MENU_WITH_CAL_LOCK` @`0x3f780` (skip CAL-locked items).

### Key dispatch — `KEY_DISPATCH_KEYCODE_HANDLER` @`0x3d340`
Reads a keycode (auto-repeat via `KEY_GET_AUTOREPEAT_KEYCODE`, else `DISPBOARD_KEY`),
binary-searches the menu-nav keycode table (`KEYCODE_ARRAY_0003d3ce`: `0x41,0x42,0x43,0x4a,
0x50,0x51,0x54,0x55,0x5a,0x61`) and jumps to the handler. In remote mode, OUTPUT ON/OFF
aborts the trigger model and re-inits comm. The named handlers are the
`FUNCTION_KEYCODE__*` family: arrows (`__LEFT_ARROW` @`0x3ea26`, `__RIGHT_ARROW` @`0x3eb24`),
`__EDIT` @`0x3d732`, `__TRIGGER` @`0x3e510`, `__ON_OFF` @`0x3f2b8`, etc. ENTER descends /
confirms (sets `gMenuEnterSelected`); EXIT ascends via `parentMenu`.

---

## 4. Setup vs trigger dispatch

Each `MENU_ITEM_STRUCT` carries two `MENU_FN` pointers (`void(void)`):

- **`setupFunction`** — invoked to *enter and display* the item (its current value, options).
  The current item's setup fn is cached in `gMenu_Setup_Function` and called from
  `MENU_CALL_SETUP` when `gMenuSetupPending`.
- **`triggerFunction`** — invoked on **ENTER** to *act on* the item. Called by `MENU_SELECT`
  for the outgoing current item (`(*gMenu_Current->triggerFunction)()`).

These are the `MENU_SETUP_*` / `MENU_ACTION_*` function families (≈443 menu functions). E.g.
`MENU_ITEM_COMMUNICATIONS_SETUP` pairs `MENU_SETUP_…`/`MENU_ACTION_COMMUNICATIONS_SETUP`.

---

## 5. Menu text rendering

`MENU_RENDER_DISPLAY_LINES` @`0x4a1ce` copies the current item's `menuLines`
(`MENU_TEXTS.title` / `.line_left` / `.line_right`) into the display line buffer
`gDISP_LINES_DATA`, with **per-model text substitution** (e.g. the voltage-protection menu
swaps its strings by `gHARDWARE_CONFIG.deviceModelId` — 2410/2420/2430/2440). The display is
then pushed through the VFD pipeline ([DISPLAY.md](DISPLAY.md)). Multi-field items use
`gMENU_STR_INDEX` to track which sub-field (digit/element) is active.

---

## 6. Value editing

Editable items (GPIB address, baud, limits, source levels, date/time) use a digit-cursor
editor over an 8-byte value `gMENU_EDIT_VALUE` (`0x807ef2`, Pascal double):

| Function | Addr | Role |
|---|---|---|
| `MENU_EDIT_PROCESS_KEY` | `0x4d89a` | main editor: digit entry, cursor, apply |
| `MENU_EDIT_INIT_DIGIT_CURSOR` | `0x40e0e` | set the initial cursor/field |
| `MENU_EDIT_MOVE_CURSOR` | `0x4c8cc` | ◄ ► move the edit cursor |
| `MENU_EDIT_COMPUTE_DIGIT_WEIGHT` | `0x4137c` | decimal weight of the cursor digit |
| `MENU_EDIT_COMPUTE_DIGIT_STEP` | `0x4d2c0` | ▲▼ increment/decrement step |
| `MENU_EDIT_SHIFT_DECIMAL` | `0x4e64e` | reposition the decimal point |
| `MENU_EDIT_ADJUST_DATETIME` | `0x4e3a4` | date/time field editor |
| `MENU_VERIFY_VALUE_RANGE(v,min,max)` | `0x40546` | **range clamp**: sets `gValueErrorFlag_TooSmall`/`_TooLarge` and shows "TOO SMALL"/"TOO LARGE" (0.0001 tolerance) |
| `MENU_IS_VALUE_EDIT_ACTIVE` | `0x421c4` | is an edit field active |

Edit state globals: `gMENU_EDIT_VALUE` `0x807ef2`, `gMENU_EDIT_CURSOR_POS` `0x8027c9`,
`gMENU_NUMERIC_FIELD_VALUE` `0x805120`, `gMENU_ITEM_HAS_EDIT_FIELD` `0x805549`; the entered
numeric value is read back from `gMN_OUTPUT_STRUCT[0].doubleValue`.

> **Flagged (ambiguous):** `gMenuEditValueA_maybe` (`0x80841c`), `gMenuEditValueB_maybe`
> (`0x808444`), `gMenuSetupTemp_maybe` (`0x803814`), `gMenuTemp_29d8/462c_maybe`,
> `gMenuWord_54ec/54ee/54f4/54f6_maybe` — shared menu-edit scratch whose exact roles are not
> individually proven; left `_maybe` per the naming discipline rather than guessed.

---

## 7. Persistence (front-panel → command queue → config → EEPROM)

A confirmed menu action **enqueues an internal command** rather than writing config itself.
Example (`MENU_ACTION_GPIB_ADDRESS` @`0x481d6`):

```c
if (gMenuEnterSelected) {
  value = round(gMN_OUTPUT_STRUCT[0].doubleValue);
  FP_CMD_QUEUE_ADD_CMD_AND_LONG(COMMAND_ID_DIAGNOSTIC_KEITHLEY_GPIB, value);
}
```

`FP_CMD_QUEUE_ADD_CMD_AND_LONG(COMMAND_ID, value)` posts to the **front-panel command queue**,
drained by `FP_CMD_QUEUE_PROCESS` in the scheduler and executed by the *same* command
executor that runs remote SCPI — so a key press and a bus command take identical effect.
`MENU_ACTION_COMMUNICATIONS_SETUP` @`0x48118` posts `COMMAND_ID_SELECT_GPIB_or_RS232` (0 = GPIB,
1 = RS-232); the RS-232 actions post baud/bits/parity/terminator/flow commands
(`MENU_ACTION_RS232_*` @`0x482b4`+).

The command handler updates the config RAM structs (`gCONFIG_0x19E` / `gCONFIG_COMM`) and, for
persistent settings, writes them to the **24LC16B EEPROM** via `CONFIG_SAVE_TO_NVRAM`
@`0x285ac` → the bit-banged `I2C_*` driver (`I2C_WRITE_DATA` @`0x50b62`, `I2C_INIT` @`0x50a98`,
etc.). `CONFIG_SAVE_TO_NVRAM` is also invoked by `SYSTEM_PRESET_RESET_APPLY` and
`FACTORY_RESET_RAM_STATE`. **Changing the interface** (GPIB↔RS-232) re-initialises the comm
subsystem (the documented "interface change → power-on reset" behaviour), routed through
`COMMAND_ID_SELECT_GPIB_or_RS232`. See [CALIBRATION.md](CALIBRATION.md) for the CAL submenu's
protected NVRAM writes and `SUMMARY.md`/`parse_flash.py` for the EEPROM layout.

---

## 8. Key symbols (quick reference)

**Tree:** `MENU_ITEM_STRUCT` (28 B) · `MENU_TEXTS` (12 B) · `MENU_10_STRUCT` (40 B) · root
`MENU_ITEM_STRUCT_MAIN_MENU` `0x652ac` → `MENU_10_STRUCT_00063c82`.

**Navigation:** `MENU_SELECT` `0x3faac` · `MENU_CALL_SETUP` `0x3ceee` · `MENU_MODIFY_BY_CONFIG`
`0x3fd94` · `MENU_GET_PARENT` `0x3f89a` · `MENU_GET_NEXT_MENU_WITH_CAL_LOCK` `0x3f780` ·
`MENU_RENDER_DISPLAY_LINES` `0x4a1ce`.

**Key dispatch:** `KEY_DISPATCH_KEYCODE_HANDLER` `0x3d340` · `KEY_GET_NEXT_KEYCODE_BY_MODE`
`0x3cfe0` · `KEY_GET_AUTOREPEAT_KEYCODE` `0x3d54a` · `FUNCTION_KEYCODE__{LEFT,RIGHT}_ARROW`
`0x3ea26`/`0x3eb24` · `__EDIT` `0x3d732` · `__TRIGGER` `0x3e510` · `__ON_OFF` `0x3f2b8`.

**State:** `gMenu_Current` `0x807ede` · `gMenuCurrentSelectionIndex` `0x807eee` ·
`gMenuEnterSelected` `0x8050f9` · `gMenu_Setup_Function` `0x805624` · `gMenuSetupPending`
`0x80855c` · `gMenuForUnit` `0x807ee2` · `gMENU_STR_INDEX` `0x805258`.

**Editing:** `MENU_EDIT_PROCESS_KEY` `0x4d89a` · `MENU_VERIFY_VALUE_RANGE` `0x40546` ·
`MENU_EDIT_MOVE_CURSOR` `0x4c8cc` · `MENU_EDIT_COMPUTE_DIGIT_STEP` `0x4d2c0` ·
`gMENU_EDIT_VALUE` `0x807ef2` · `gMENU_EDIT_CURSOR_POS` `0x8027c9`.

**Persistence:** `FP_CMD_QUEUE_ADD_CMD_AND_LONG` · `CONFIG_SAVE_TO_NVRAM` `0x285ac` ·
`I2C_WRITE_DATA` `0x50b62` · `MENU_ACTION_COMMUNICATIONS_SETUP` `0x48118` ·
`MENU_ACTION_GPIB_ADDRESS` `0x481d6`.

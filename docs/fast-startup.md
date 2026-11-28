# Fast startup: design and current limits

This is a design note, not a claim that fast startup works. It records what was
verified in the tree at commit `4c53fc9c3` and what remains to be built.

## Goal

Windows "Fast Startup" hibernates the kernel and driver session, not the user's
applications. The next start restores that image and begins a fresh user
session. It is a hybrid of a cold boot and a suspend to disk, not a way to get
applications back.

Vinix already has a suspend to disk (`echo disk > /sys/power/state`) that saves
*every* allocated page, including every process, and returns into the process
that asked for the sleep when the image is entered. That is full hibernation.

## What exists today

- `kernel/hibernate/format.v` — image layout, checksums, machine identity.
  PR #280 adds an image kind so a full image and a kernel-session image can be
  told apart.
- `kernel/hibernate/snapshot_amd64.v` — `prepare()`, `take_snapshot()`,
  `write_image()`, `withdraw_image()`, `release()`.
- `kernel/hibernate/resume_amd64.v` — `resume_at_boot()` looks for an image
  after the disk drivers come up and before any filesystem is mounted.
- `kernel/syspower/hibernate_amd64.v` — the suspend-to-disk state machine.
- `kernel/x86/wake/` and `asm/x86_64/{wake_context,hibernate}.S` — save and
  restore processor context. `sleep_processor(callback)` behaves like
  `setjmp`: the second return from an image skips the callback entirely.

## Proposed mechanism

Take the kernel-session image **during boot**, before userland starts:

1. `kmain_thread()` brings up PCI, DMA and the disk drivers
   (`kernel/main_amd64.v:104-135`). At `:143` it calls
   `hibernate.resume_at_boot()` before mounting any disk root.
2. If an image is found, `resume_at_boot()` enters it. The saved context must
   be the boot-time call site, so the restored kernel continues down
   `kmain_thread` into a fresh mount and a fresh `/sbin/init`.
3. If no image is found and `vinix.fastboot=` is set, take a snapshot of this
   clean boot state and write it to the device named by `vinix.hibernate=`.
   Then resume the machine normally and continue booting.
4. On the next boot, `resume_at_boot()` restores that image and the restored
   kernel steps 2.

This reuses the existing page selection, write path, machine identity checks,
and `x86_hibernate_enter` loader. No new sleep state or process teardown is
needed: choosing the capture point before userland *is* the policy.

### Preconditions at the capture point

`wake.sleep_processor()` requires interrupts off, the calling thread on CPU 0,
and every other processor parked (`kernel/x86/wake/context.v:219-224`).
`hibernate.prepare()` requires the image device to be open and this system's
to write, and enough free pages to hold a copy of every page in use.
`take_snapshot()` must not allocate, sleep, or hold a lock the resumed kernel
needs, and it raises the block fence after the copy. The image device must be
the only writer from the snapshot until power-off.

### Resume flavour

The restored kernel returns from `sleep_processor()` at the boot capture site,
not in `syspower/hibernate_amd64.v`. The restoration block in
`hibernate_here()` (`hibernate_amd64.v:171-222`) must therefore be factored
into a reusable function and called from both places: I/O APIC, PIT, HPET and
RTC restore, wake-status consumption, DMA unit resume, secondary CPUs,
interrupts, `hibernate.resumed()`, power-lost device restore, PCI/display
restore and ACPI event resume. Clock advancement and `set_power_lost(true)`
are appropriate here because the restore is still happening after a power cut.

### Header and devices

PR #280 adds the kind field at the end of `Header`, leaving v1 field offsets
unchanged. Only one header slot exists per image device, so a fast-startup
image and a full hibernation image cannot coexist on one device; either the
installer reserves a second device/partition or the two modes are mutually
exclusive. `look_for_images()` must not treat a kernel-session image as a
"full image waiting" that blocks mounts.

## Blockers, in dependency order

1. **Encryption.** The image is a copy of memory. `prepare()` refuses a plain
   image whenever block encryption was used
   (`snapshot_amd64.v:157`). Vinix has AES-256-XTS (`kernel/aesxts`) and a
   reusable HMAC-SHA256 (`pager.authenticate`), but no kernel KDF, no AEAD, no
   TPM, and no way to read a passphrase before filesystems are mounted: the
   console and keyboard are created at `main_amd64.v:202`, after the resume
   point at `:143`. A key source must be designed before encryption can be
   claimed. A passphrase prompt needs a polled early input path; unattended
   operation needs a TPM or an equivalent secure-enclave driver.
2. **Verification.** Building a full kernel on this Windows host fails
   because V emits `\\r` inside generated inline-asm clobbers; normalising
   that in the generated C lets Clang compile `obj/blob.c`, but the native
   generator step then fails to resolve its local modules. A Linux host is
   needed before a boot-path change can be boot-tested in QEMU.
3. **AArch64.** `kernel/hibernate/hibernate_arm64.v` is a stub and
   `kernel/syspower/platform_arm64.v` stubs every disk hook. There is no arm64
   `sleep_processor`, wake assembly or resume entry. This is a port with its
   own wake, GIC/IOMMU state, FDT identity checks and M1 firmware handoff, not
   an extension of the x86 path.

## Test plan

- Host: format and policy tests in `tests/hibernate`, including kind
  validation and machine-identity invalidation.
- QEMU x86-64: repeated boot/snapshot/restore cycles; assert the desktop
  starts and no user process from the previous session survives; assert the
  image is refused and a cold boot happens after a kernel or command-line
  change; measure time to desktop against a cold boot.
- QEMU: verify the fence still prevents any write after the snapshot, and
  that a torn image is not entered.
- Kernel built with `-gc none -manualfree`: repeat cycles and check that
  `/proc/slabinfo` and `/proc/meminfo` stay flat.

Until those gates pass on a real build, none of this should be described as a
working fast-startup feature.

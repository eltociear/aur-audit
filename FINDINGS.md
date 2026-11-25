# What we found scanning 3,300 AUR packages

This is the research behind `aur-audit`: a scan of the most-voted corner of the Arch User
Repository, a random sample of the rest, and a sample of the packages named in the June 2026
campaign list, all run with this exact engine. As with
[homebrew-audit](https://github.com/eltociear/homebrew-audit/blob/main/FINDINGS.md) and
[npm-audit](https://github.com/eltociear/npm-audit/blob/main/FINDINGS.md), the engine was
calibrated so that "clean" means clean before any number is reported.

## Method

1. Took the AUR metadata dump (`packages-meta-v1.json.gz`, 126,658 packages / 118,980 package
   bases) on 2026-11-25.
2. **Calibration set (2,000):** the top 2,000 package bases by votes, then popularity.
3. **Held-out set (1,000):** a random sample (seed `20261125`) of the remaining, not-out-of-date
   package bases. It was scanned once, with the rule set committed *before* the scan
   (commit `84c5bbc`).
4. **Campaign sample (300):** community tracking of the June 2026 incident lists 1,935 package
   names. 1,813 of them still exist; 300 were sampled at random (seed `7`).
5. Each package's full repo was fetched: PKGBUILD, `.install`, alpm hooks, units, patches, shipped
   scripts. It came from Arch's read-only GitHub mirror of `aur.git`, falling back to the AUR
   snapshot endpoint. Nothing was built, sourced or executed.

## Headline

| Result | Calibration (2,000) | Held-out (1,000) | Campaign sample (300) |
| --- | --- | --- | --- |
| CRITICAL | **0** | **0** | **0** |
| HIGH | 1 (0.05%) | 3 (0.3%) → 2 after one fix | 0 |
| MEDIUM | 24 | 3 | 0 |
| LOW (`http://` but checksummed, `systemctl enable` in a hook) | 247 | 59 | 44 |
| Same signatures, context-blind (HIGH or worse) | 278 (13.9%) | 88 (8.8%) | 45 (15.0%) |

**No package in the 3,300 currently carries a malicious pattern.** That includes the 300 sampled
from the June 2026 campaign list. Their current versions contain none of the campaign's published
indicators and trip no HIGH rule, which is consistent with the cleanup having reached them.

The remaining HIGHs are each a real instance of the pattern with benign intent, stated here as
observed patterns, not verdicts:

- a root `post_install` that writes a dotfile into its own service user's home (calibration);
- a root hook that runs `pnpm add -g <package>`, installing unpinned npm code as root on every
  user's machine (held-out);
- a root hook that copies files into `~/.claude/skills/` (held-out).

The fourth held-out HIGH was a real false positive: a `/usr/bin/printf` user message that wasn't
recognised as output. It was fixed *after* the held-out scan (and a regression test added), so the
blind number above is the 3, not the 2.

## Install scriptlets don't fetch, which is why the June 2026 injection stands out

23.8% of the top 2,000 ship a `.install` scriptlet (8.8% of the random sample). Those run as root
on every install and upgrade. Across the 476 in the top 2,000 and the 88 in the random sample:

| Done from a root install scriptlet | Top 2,000 | Random 1,000 |
| --- | --- | --- |
| npm / bun / pip / cargo / go **install** | **0** | 1 |
| Network fetch (`curl`, `wget`, `git clone`) | **0** | 0 |
| Pipe-to-shell, decoded exec, reverse shell | 0 | 0 |
| Writes a systemd unit / cron / shell rc / dotfile on the live system | 1 | 1 |
| `systemctl enable` / `.wants/` link | 15 | 6 |
| Sets setuid/setgid on the live system | 7 | 0 |

Legitimate scriptlets print messages, run `systemd-sysusers`, update caches and occasionally
enable a service. The June 2026 injection was one added line, `npm install atomic-lockfile` (or
`npm install lockfile-js`, `bun install js-digest`), in exactly that file. **That shape does not
occur** in any of the 476 most-used scriptlets. A package-manager install in a root hook is scored
HIGH on its own, and the campaign's package names are CRITICAL.

## The noise: what looks dangerous in an AUR repo but isn't

Context-blind, the same signatures flag 13.9% of the top 2,000. Every one of those is a false
positive or one of the benign-intent cases above. The drivers, in packages:

| Signal | Top 2,000 | Why it's noise |
| --- | --- | --- |
| `curl` / `wget` / `git` outside a hook | 216 | Version scraping in `pkgver()`, `DLAGENTS=` overrides, `curl` in `depends=()`, wrapper scripts that self-update |
| `npm` / `pip` / `cargo` outside a hook | 44 | `npm ci` in `build()` is how Electron packages build; `cargo fetch --locked` in `prepare()` |
| Shell-rc / home-dir writes outside a hook | 27 | `echo "add this to your ~/.bashrc"` messages; launcher scripts that set up `~/.app` on first run |
| Pipe-to-shell outside execution | 3 | A CI config (`.travis.yml`) in the package repo. CI files run on the CI service, never on your machine |
| Multi-line `echo "…"` / `cat << \EOF` messages | – | Install advice spread over several lines of a quoted string or heredoc |
| Paste-host names | – | A local file called `temp.sh` is not the temp.sh file host |
| `.wants/` symlinks in a hook | – | `ln -s /usr/lib/systemd/system/x.timer …/timers.target.wants/` is `systemctl enable`, not a new unit |
| Vendor-hosted sources | – | `linux.dropbox.com` and `mega.nz/linux/repo` are the vendors' own channels, not share links |

Every one is a capability, not an attack. The attack is the **location**: the same `npm install`
that is routine in `build()` is the June 2026 payload in `post_install()`. `aur-audit` classifies
every line by where it runs and only scores what runs in the dangerous place.

## Other observations (MEDIUM / LOW, aggregate)

- **Plaintext sources:** 239 of the top 2,000 (12.0%) fetch a checksummed `http://` source (LOW).
  7 have an `http://` source with no checksum at all (MEDIUM): anyone on the network path can
  replace those bytes.
- **`SKIP` on a release tarball:** 105 of the top 2,000 (5.3%) skip the checksum for a non-VCS
  source, usually an unpinned "latest" download. Reported as info.
- **Code that runs when the PKGBUILD is merely sourced:** 7 of the top 2,000 call `curl` at the
  PKGBUILD's top level to scrape a version, checksum or download URL. That runs on every
  `source PKGBUILD` (AUR helpers, `.SRCINFO` generation) before anyone has reviewed or built.
- **`sudo` inside `build()`/`package()`:** 0 in the top 2,000, 2 in the random sample. makepkg
  refuses to run as root, so these escalate behind its back to write outside `$pkgdir`.
- **`-bin` packages built from an unrelated git repo** (the July 2025 CHAOS RAT shape): **0** in
  all 3,300. Of the 289 `-bin` packages scanned, none clones a repository whose owner isn't the
  upstream's.
- **Personal file hosts:** 2 of the top 2,000 download from a Dropbox share link.

## Known incidents and how they look to the scanner

- **June 2026, atomic-lockfile / js-digest.** Arch Linux announced an
  [active AUR malicious packages incident](https://archlinux.org/news/active-aur-malicious-packages-incident/)
  on 2026-06-12: a high volume of malicious package adoptions and updates. Community tracking
  ([lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check)) records ~1,935
  affected names and the injected lines `npm install atomic-lockfile`, `npm install lockfile-js`
  and `bun install js-digest` in `.install` / PKGBUILD files. The npm packages carried an ELF
  credential stealer (`atomic-lockfile` ran it from its `preinstall` hook). That is the `pkgmgr_in_hook` + `campaign_ioc` shape:
  CRITICAL. Canary: `tests/canaries/june2026-injection`.
- **July 2025, CHAOS RAT.** `librewolf-fix-bin`, `firefox-patch-bin` and `zen-browser-patched-bin`
  had PKGBUILDs pulling from a GitHub repository that served the CHAOS remote-access trojan, and
  were removed less than two days later
  ([The Register](https://www.theregister.com/2025/07/22/arch_aur_browsers_compromised/),
  [LinuxSecurity](https://linuxsecurity.com/features/chaos-rat-in-aur)). That is the
  `bin_vcs_source` shape (a `-bin` package whose source is a git repo unrelated to the upstream):
  MEDIUM, a "read this PKGBUILD" flag. What the payload does depends on the script in that
  repo, which lives outside the package repo. Canary: `tests/canaries/chaos-rat-shape`.

## Takeaways

1. **Diff the `.install` file on every upgrade.** It runs as root, it is short, and in the
   most-used packages it never fetches or installs anything. Any `npm`/`bun`/`pip`/`curl` there
   is a reason to stop.
2. **Gate builds, don't just review them.** `PreBuildCommand = python3 aur_audit.py .` in paru,
   or a wrapper around yay, makes the scan run on every package without relying on attention.
3. **Score location, not capability.** `npm install`, `curl` and `~/.bashrc` appear in hundreds
   of benign recipes. They are a finding only where they run as root or before review.
4. **Orphaned packages are the attack surface.** The June 2026 wave adopted orphans. A package
   that changed maintainer recently deserves a full read, whatever the scanner says.

---

Run it yourself: `python3 aur_audit.py --aur <package>`. Findings are pattern matches warranting
human review, not verdicts. No package in the scanned corpus is accused of anything. Suspected
malicious packages should be reported to the
[aur-general mailing list](https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/)
and the maintainer, not published as unverified accusations.

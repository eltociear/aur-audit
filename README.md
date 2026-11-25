# aur-audit

**Security-scan AUR packages before you build or install them.** It reads the PKGBUILD, the
`.install` scriptlet, alpm hooks, systemd units and any scripts shipped in the package repo.
Zero dependencies, one file, MIT.

```bash
python3 aur_audit.py --aur some-package            # fetch the AUR snapshot and scan it
python3 aur_audit.py .                             # the package dir you just cloned (skips src/ and pkg/)
python3 aur_audit.py --installed-foreign           # every foreign package on this machine (pacman -Qqm)
```

```
$ python3 aur_audit.py tests/canaries/june2026-injection
🔴 tests/canaries/june2026-injection  [CRITICAL]  score=40  (2 findings, 1 info)
    CRITICAL Known Campaign Indicator (canary-tool.install:2, hook)
             npm install atomic-lockfile >/dev/null 2>&1 || true
    HIGH     Package-Manager Install in Root Hook (canary-tool.install:2, hook)
             npm install atomic-lockfile >/dev/null 2>&1 || true
```

## Why this exists

The AUR is user-submitted shell. `makepkg` runs `prepare()`/`build()`/`package()` as you.
pacman runs the `.install` scriptlet (`post_install`, `post_upgrade`, …) and any alpm hook
**as root**. The PKGBUILD's top level runs whenever *anything* sources it, including AUR helpers
generating `.SRCINFO`. The AUR's own advice is to read every PKGBUILD and install script before
building. In practice that review is skipped, and attackers know it:

- **June 2026.** Arch Linux announced an
  [active AUR malicious packages incident](https://archlinux.org/news/active-aur-malicious-packages-incident/):
  a high volume of malicious package adoptions and updates. Community tracking
  ([lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check)) records the
  injection as a single added line in `.install` / PKGBUILD files, such as `npm install atomic-lockfile`,
  `npm install lockfile-js` or `bun install js-digest`. Each pulled an npm package that carried
  an ELF credential stealer.
- **July 2025.** Three `-bin` browser packages, `firefox-patch-bin`, `librewolf-fix-bin` and
  `zen-browser-patched-bin`, had PKGBUILDs that pulled from a GitHub repository serving the
  CHAOS remote-access trojan. They were removed less than two days later
  ([The Register](https://www.theregister.com/2025/07/22/arch_aur_browsers_compromised/),
  [LinuxSecurity](https://linuxsecurity.com/features/chaos-rat-in-aur)).

Neither is a CVE, so CVE scanners can't see them. Both are visible in the package recipe.
That recipe is what this tool scans.

| Pattern | Severity |
| --- | --- |
| Pipe-to-shell (`curl … \| sh`, `bash <(curl …)`, `eval "$(wget …)"`) | CRITICAL |
| Decoded-then-executed payloads (`base64 -d \| sh`, `eval "$(printf '\x..')"`) | CRITICAL |
| Reverse shells (`/dev/tcp/…`, `nc -e`, `socat exec:`) | CRITICAL |
| Credential exfiltration (`~/.ssh/id_*`, `.npmrc`, browser profiles … sent to a non-upstream host) | CRITICAL |
| `/etc/ld.so.preload` writes (system-wide library injection) | CRITICAL |
| Destructive commands (`rm -rf /`, `dd of=/dev/sda`) | CRITICAL |
| Published indicators of the June 2026 campaign | CRITICAL |
| npm / bun / pip / cargo / gem / go **install inside a root hook** | HIGH |
| Network fetch inside a root hook (`curl`, `wget`, `git clone` in `post_install`) | HIGH |
| Source or call to a paste site, anonymous file host, Discord CDN, tunnel, webhook collector, Telegram bot or `.onion` | HIGH |
| Persistence from a hook (systemd unit, cron, autostart, shell rc, `/etc/profile`) | HIGH |
| sudoers / PAM / `authorized_keys` / `usermod -aG wheel` / `chpasswd` | HIGH |
| Firewall / SELinux / AppArmor / auditd switched off · shell-history or log wiping | HIGH |
| `http://` source with `SKIP` / no checksum | MEDIUM |
| `-bin` package that builds from an unrelated git repo (the CHAOS RAT shape) | MEDIUM |
| Network call at PKGBUILD top level (runs on every `source PKGBUILD`) | MEDIUM |
| `sudo` / `pkexec` inside the build · setuid or 777 set from a hook · obfuscated blobs · Google Drive / Mega / MediaFire sources | MEDIUM |
| Pipe-to-shell *advised* to the user in an `echo` | MEDIUM |
| `http://` source that is still checksummed · `systemctl enable` from a hook | LOW |

That's 24 scored patterns (58 regex signatures, plus 5 parse-based or file-level checks), plus 6
informational ones. Deterministic, no LLM, and nothing is built or executed.

## Bash-aware, so it stays quiet

The same line means different things in different places. `npm ci` in `build()` is how every
Electron package builds. `npm install <name>` in `post_install()` runs as root, outside
makepkg's checksums, on every user's machine, and it is exactly what the June 2026 injection
looked like. So every line is classified by where it runs:

| Context | Runs | Treated as |
| --- | --- | --- |
| PKGBUILD top level | whenever the PKGBUILD is sourced | risk (network calls here are MEDIUM) |
| `prepare` `build` `check` `package` `pkgver` | makepkg, as you | risk, but language package managers and fetches are `info` |
| `pre/post_install`, `pre/post_upgrade`, `.install` top level, alpm hook `Exec=` | pacman, **as root** | risk, strictest rules |
| `pre/post_remove` | pacman, as root | risk, but deleting the package's own files is cleanup |
| systemd unit `Exec*=` lines | the service | risk |
| heredoc bodies / shipped scripts | later, as the user | malicious-only patterns |
| `echo` / `printf` / `msg` text, READMEs, CI configs (`.travis.yml`, `.github/`) | never on your machine | context (pipe-to-shell advice is capped at MEDIUM) |

Sources are parsed, not grepped. `source=()` and `source_<arch>=()` entries are expanded
(`$url`, `$pkgver`, `${_var}`) and aligned with every checksum array. That separates
`SKIP` on a git source (normal) from `SKIP` on a release tarball, and lets a vendor's own host
(Dropbox's client from `linux.dropbox.com`) be told apart from a personal share link.

The same signatures with no context rules flag **13.9% of the 2,000 most-voted AUR packages**
as HIGH or worse. With them: **0 CRITICAL and 1 HIGH (0.05%)**, and on a random held-out 1,000
scanned once with frozen rules, **0 CRITICAL and 3 HIGH (0.3%)**, two of which are what the rule
targets (a root hook running `pnpm add -g`, a root hook copying into a home dotdir). None of the
476 most-used `.install` scriptlets runs a package manager or a network fetch. That is why the
June 2026 one-line injection is so visible to this scanner. All 17 canaries in `tests/` trip at
the right severity.

**Full results: [FINDINGS.md](FINDINGS.md)**

## Usage

```bash
python3 aur_audit.py PKGBUILD foo.install             # local files
python3 aur_audit.py path/to/package-dir              # a cloned package (skips src/ and pkg/)
python3 aur_audit.py --aur yay paru-bin               # AUR packages (resolves pkgbase via the RPC)
python3 aur_audit.py --installed-foreign              # everything from `pacman -Qqm`
python3 aur_audit.py --text 'post_install() { … }'    # a snippet
python3 aur_audit.py --json --aur foo                 # machine-readable
python3 aur_audit.py --verbose …                      # also print info-tier context
python3 tests/run_tests.py                            # canary + benign regression suite
```

Exit code is `2` if any package is HIGH or CRITICAL, so it can gate a build.

### Gate every AUR build

**paru** runs `PreBuildCommand` (in the `[bin]` section of `~/.config/paru/paru.conf`) in each
package's directory before building, and aborts the build if it exits non-zero:

```ini
[bin]
PreBuildCommand = python3 /path/to/aur_audit.py .
```

**yay, or any helper**: wrap the install so the scan runs first:

```bash
# ~/.bashrc / ~/.zshrc
aurs() {
  python3 /path/to/aur_audit.py --aur "$@" || { echo "aur-audit: review the findings above"; return 1; }
  yay -S "$@"
}
```

**Plain makepkg**:

```bash
python3 /path/to/aur_audit.py . && makepkg -si
```

## Caveats

- It's static. A `-bin` package whose release tarball is itself malicious looks exactly like one
  whose tarball is fine. This scans what the recipe **does**, not what it downloads.
- An npm/bun/pip install in `build()` is reported as `info`, not risk, because that's how
  most JavaScript and Python packages build. Review `--verbose` output for packages you don't know.
- Findings are pattern matches for human review, not verdicts. If you find an active injection,
  report it to the [aur-general mailing list](https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/)
  and the package maintainer.

Sibling projects: [homebrew-audit](https://github.com/eltociear/homebrew-audit) (Homebrew
formulae, casks & taps) · [winpkg-audit](https://github.com/eltociear/winpkg-audit) (Scoop,
winget, Chocolatey) · [npm-audit](https://github.com/eltociear/npm-audit) ·
[mcp-audit](https://github.com/eltociear/mcp-audit) (MCP servers & agent skills).

MIT © Ikko Eltociear Ashimine

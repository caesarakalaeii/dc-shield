{
  # Keep this line accurate and one line long: `nix flake metadata` prints it,
  # and it is the first thing a cold agent learns about the repo.
  description = "dc-shield -- educational Quart/Hypercorn honeypot demonstrating Discord geoblocking and browser fingerprinting. Run `nix flake show` for the command map.";

  # nixpkgs is the only input, on purpose.
  #
  # flake-utils would buy exactly one thing here -- eachDefaultSystem -- which is
  # the three-line genAttrs below. In exchange it costs a second lock node in
  # every repo (flake-utils transitively pulls `systems`), a second upstream that
  # can break one repo and not the others, and a hardcoded system list this repo
  # cannot edit. That list is currently broken: it still contains x86_64-darwin,
  # which now throws (see `systems` below).
  #
  # nixos-unstable is the same channel the author's own NixOS config tracks, so
  # `nix develop` here and `nixos-rebuild` there resolve the same store paths and
  # share one cache.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    # `...` rather than a closed { self, nixpkgs }: adding a second input later
    # would otherwise fail with "called with unexpected argument '<name>'".
    #
    # `self` is bound because the commands need it: it is the only handle a
    # wrapper has on this repo that does not depend on the caller's cwd. See
    # rootPreamble.
    { self, nixpkgs, ... }:
    let
      lib = nixpkgs.lib;

      # x86_64-darwin is deliberately absent. nixpkgs 26.11 replaced that whole
      # attribute set with a `throw`. genAttrs is lazy, so plain `nix develop` on
      # Linux would not notice -- it detonates later, on
      # `nix flake check --all-systems`.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      # Stand-in for flake-utils.lib.eachDefaultSystem. Passes `pkgs` rather than
      # a system string, because that is what every call site below wants.
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # ======================================================================
      # PER-REPO BLOCK 1 -- the toolchain
      # ======================================================================
      # Every runtime and test dependency in requirements.txt exists in nixpkgs
      # for python313, so the interpreter is built with them baked in and this
      # repo needs NO `setup` verb and NO network: a cold `nix develop -c
      # dev-test` runs the suite offline. Verified 141 passed / 26 deselected.
      #
      # The consequence to internalise: there is no .venv and no pip in here. To
      # add a dependency, add it to requirements.txt (for Docker/CI) AND to this
      # list. Do not "fix" a missing package by creating a .venv beside this env
      # -- you then get two interpreters, and `dev-test` and a bare `pytest`
      # silently disagree about which one is live.
      #
      # python313 to match the Dockerfile (python:3.13-slim), not CI's 3.11:
      # the image is what actually ships, and pinning by major rather than the
      # rolling `python3` alias keeps a nixpkgs bump from moving the interpreter
      # under an agent mid-task.
      pythonEnv =
        pkgs:
        pkgs.python313.withPackages (ps: [
          # ---- runtime ----
          ps.quart
          ps.hypercorn
          ps.requests
          ps.user-agents
          # withVoice = false drops PyNaCl, libopus and the FULL ffmpeg from the
          # closure: 1.4 GiB -> 412 MiB. Justified because nothing in this repo
          # touches Discord voice (no VoiceClient, no FFmpegAudio) -- it only
          # posts embeds and runs a slash-command bot. Re-enable it the day a
          # voice feature lands, and expect the closure to quadruple.
          (ps.discordpy.override { withVoice = false; })
          # requirements.txt also lists `ipaddress`. That PyPI distribution is
          # the Python 2 backport of the stdlib module and is a no-op on 3.13,
          # which is why there is no nixpkgs attr for it. Nothing to add here.

          # ---- tests ----
          ps.pytest
          ps.pytest-asyncio # pytest.ini sets asyncio_mode = auto
          ps.pytest-cov # pytest.ini's addopts hard-require --cov
          ps.pytest-mock
          ps.httpx

          # ---- code quality (mirrors CI's black/flake8 steps) ----
          ps.black
          ps.flake8
          ps.mypy
        ]);

      toolchain = pkgs: [
        # ---- this repo's ecosystem ----
        (pythonEnv pkgs)
        # curl earns its place in a repo whose only artifact is an HTTP service:
        # without it there is no way to exercise `dev-run` from inside the shell.
        pkgs.curl

        # ---- present in every repo in the fleet ----
        pkgs.git
        pkgs.jq
        pkgs.gnumake
      ];

      # ======================================================================
      # PER-REPO BLOCK 2 -- libraries that get dlopened, not linked
      # ======================================================================
      # Empty on purpose, and this is the degenerate case the template supports.
      # LD_LIBRARY_PATH exists to rescue manylinux wheels, whose bundled .so
      # files are dlopened where neither patchelf nor the nix linker can see
      # them. Every dependency here is built by nixpkgs and already has its
      # RPATH, so there is nothing to rescue -- and the export is skipped
      # entirely rather than clobbering an ambient value for no reason.
      nativeLibs = pkgs: [ ];

      # ======================================================================
      # PER-REPO BLOCK 3 -- constant environment variables
      # ======================================================================
      # Only values that are constants belong here. Anything that must READ an
      # existing value (LD_LIBRARY_PATH), UNSET something (SOURCE_DATE_EPOCH) or
      # touch the work tree goes in the shellHook further down.
      #
      # Applied to BOTH surfaces -- the dev shell and every `nix run` wrapper --
      # so a command cannot behave differently depending on how it was invoked.
      envVars = pkgs: {
        # main.py logs its whole startup sequence through print(). Unbuffered,
        # that output is lost to the block buffer the moment an agent pipes
        # `nix run .#run` anywhere, and the agent concludes the server hung.
        PYTHONUNBUFFERED = "1";
      };

      # ======================================================================
      # PER-REPO BLOCK 4 -- the command map
      # ======================================================================
      # THE single source of truth. It generates `apps` (so `nix run .#test`
      # works), the `dev-*` wrappers on PATH inside the shell, and `dev-help`.
      # Nothing is written twice, so `nix flake show` can never disagree with
      # what `dev-test` actually runs.
      #
      # `build` is absent, and that absence is information: this repo produces no
      # local artifact. Its deliverable is the GHCR container image, and that is
      # built by `docker build .` in CI against a daemon no flake can supply.
      #
      # `setup` exists but NOT to install dependencies -- the interpreter above
      # already carries all of them. It is here because `run` downloads ~50 MB of
      # GeoIP/ASN CSVs on first start, and an agent needs a way to pay that cost
      # once, deliberately, instead of discovering a 60-second silent stall.
      commands =
        pkgs:
        let
          # Absolute store paths, not bare names. The wrappers do put this env
          # first on PATH, so a bare `pytest` would resolve correctly today, but
          # naming the interpreter is what makes `nix run .#test` and `dev-test`
          # provably the same program regardless of what else a caller has on
          # PATH.
          py = "${pythonEnv pkgs}/bin/python";
          flake8 = "${pythonEnv pkgs}/bin/flake8";
          black = "${pythonEnv pkgs}/bin/black";
        in
        {
          setup = {
            description = "(network) prefetch the ~50 MB GeoIP + ASN CSV databases into ipdb/ so `run` starts fast";
            text = ''
              # Downloads into the tree, so it needs a real one.
              require_work_tree

              # ip_locator and asn_lookup anchor their cache to
              # os.path.dirname(__file__), i.e. $REPO_ROOT/ipdb (already
              # gitignored), so this is cwd-independent -- but the modules are
              # top-level, so they only import with the repo root on the path.
              #
              # PYTHONSAFEPATH is the other half of that anchoring, and it is not
              # cosmetic: `python -c` otherwise puts the process cwd FIRST on
              # sys.path, ahead of PYTHONPATH, so a stray ip_locator.py in the
              # caller's directory would be imported instead of this repo's and
              # the 50 MB would land wherever that file lives. Honoured since
              # 3.11; this interpreter is 3.13.
              #
              # Passing the stdlib `logging` module itself as the logger is not a
              # hack for its own sake: both loaders reach for l.info/l.error and
              # their module-level `l` defaults to None, so a plain
              # `_load_db()` dies with AttributeError. The module exposes exactly
              # the two functions they call.
              #
              # Re-running this is cheap and safe: the loaders re-download only
              # when the cached CSVs are stale.
              PYTHONSAFEPATH=1 PYTHONPATH="$REPO_ROOT''${PYTHONPATH:+:$PYTHONPATH}" \
                "${py}" -c 'import logging, ip_locator, asn_lookup; logging.basicConfig(level=logging.INFO, format="%(message)s"); ip_locator.set_logger(logging); asn_lookup.set_logger(logging); ip_locator._load_db(); asn_lookup._load_db()' "$@"
            '';
          };
          test = {
            description = "run the pytest suite (offline; integration tests deselected by pytest.ini)";
            text = ''
              # Writes .coverage, htmlcov/ and .pytest_cache, all cwd-relative.
              require_work_tree

              # This verb DOES cd, and every clause of that is load-bearing.
              # An earlier revision argued the opposite -- that pytest finds
              # pytest.ini by walking up from its arguments, so no cd is needed
              # -- and each half of that was wrong in practice:
              #   * With no arguments there are no arguments to walk up from.
              #     pytest then collects from cwd, so `nix run <url>#test` from
              #     an unrelated directory collected the CALLER's tests and
              #     printed "1 passed" while these 141 never ran. A false green.
              #   * rootdir came out as the caller's directory too, so pytest.ini
              #     never applied: asyncio_mode fell back to strict and the --cov
              #     addopts vanished. The suite silently changed shape.
              #   * .coverage, htmlcov/ and .pytest_cache are written relative to
              #     cwd, and .gitignore only covers them at the repo root.
              # The price, stated plainly: path arguments are now relative to the
              # repo root rather than to where you typed the command. `dev-test
              # tests/test_main.py` works from anywhere; `dev-test ../foo.py`
              # does not.
              cd "$REPO_ROOT"
              "${py}" -m pytest "$@"
            '';
          };
          lint = {
            description = "flake8 static analysis (the pristine tree already reports 43 findings, so exit 1 is normal)";
            text = ''
              # --isolated is load-bearing, not a shortcut. The repo's own
              # .flake8 puts inline `# ...` comments inside its multi-line
              # `ignore =` value, and flake8 >= 6 refuses to parse that:
              #   ValueError: Error code '#' supplied to 'ignore' option does
              #   not match '^[A-Z]{1,3}[0-9]{0,3}$'
              # requirements.txt asks for flake8>=6.1.0, so EVERY flake8 this
              # project can legally install crashes on its own config file, pip
              # and nix alike. CI only survives it because both flake8 steps are
              # continue-on-error. So skip the file and restate its intent here.
              #
              # Do NOT "fix" this by deleting --isolated. Fix .flake8 in its own
              # commit, then delete these flags and let the file win again.
              #
              # The default target is the repo, never the caller's cwd -- a gate
              # that passes by inspecting a stranger's files is worse than no
              # gate. No cd and no require_work_tree here though: flake8 only
              # reads, and pointing it at the read-only store copy of this
              # flake's source (what REPO_ROOT resolves to when the command is
              # run by URL from outside a checkout) yields the same 43 findings
              # as the work tree does, because that copy IS the tracked tree.
              if [ "$#" -eq 0 ]; then set -- "$REPO_ROOT"; fi
              "${flake8}" \
                --isolated \
                --max-line-length=127 \
                --extend-ignore=E203,W503,E501 \
                --per-file-ignores='__init__.py:F401' \
                --extend-exclude=htmlcov,.venv,venv,env,build,dist \
                --count "$@"
            '';
          };
          fmt = {
            description = "reformat with black (REWRITES files; 13 of 18 are not black-clean yet, so expect a large diff)";
            text = ''
              # black defaults (line length 88) on purpose: the repo ships no
              # pyproject.toml, so this is exactly what CI's `black --check
              # --diff .` compares against. Note .flake8 claims line length is
              # "handled by black" at 127 -- it is not; black is at 88 and that
              # disagreement is pre-existing.
              #
              # This verb REWRITES files, so its default target is the one thing
              # in the flake that must not be guessed: with cwd as the default,
              # `nix run /path/to/dc-shield#fmt` from an unrelated directory
              # reformatted that directory's Python. Explicit arguments are still
              # honoured verbatim, still resolved against the caller's cwd, and
              # deliberately skip the work-tree guard -- a typed-out path is an
              # instruction, not a default.
              if [ "$#" -eq 0 ]; then
                require_work_tree
                set -- "$REPO_ROOT"
              fi
              "${black}" "$@"
            '';
          };
          run = {
            description = "(network on first start) serve the Quart/Hypercorn honeypot on 0.0.0.0; run `setup` first to avoid a ~60s DB download";
            text = ''
              # Writes logs/ into the tree, so it needs a real one.
              require_work_tree

              # main.py resolves $CONFIG_PATH against the process cwd and defaults
              # it to a bare "config.json", so an unanchored launch from a
              # subdirectory silently misses the config and falls through to the
              # get_env_vars() path -- serving a different site with no error. A
              # caller-supplied CONFIG_PATH still wins.
              #
              # config.json is gitignored and absent from a fresh clone; copy
              # config/config_template.json to it first (app_port lives there).
              export CONFIG_PATH="''${CONFIG_PATH:-$REPO_ROOT/config.json}"

              # cd, because main.py builds its Logger with the cwd-relative path
              # "logs/log1.txt". Without it, launching from anywhere else scatters
              # half-written logs/ directories outside the repo, and .gitignore
              # only covers the one at the root. Cheaper here than anywhere else:
              # the server takes no path arguments to resolve against the caller,
              # so nothing about the cd can surprise the caller (`test` pays a
              # real price for it; `lint` and `fmt` do not cd at all).
              cd "$REPO_ROOT"
              exec "${py}" main.py "$@"
            '';
          };
        };

      # ======================================================================
      # GENERIC MACHINERY -- byte-identical across the fleet, do not edit
      # ======================================================================

      # Prepend, never assign: a host LD_LIBRARY_PATH may be carrying something
      # the user needs, and clobbering it breaks binaries they launch from here.
      # Linux only -- on darwin the loader variable is DYLD_*, and exporting a
      # Linux-shaped value there is at best useless.
      ldPreamble =
        pkgs:
        lib.optionalString (pkgs.stdenv.hostPlatform.isLinux && nativeLibs pkgs != [ ]) ''
          export LD_LIBRARY_PATH="${lib.makeLibraryPath (nativeLibs pkgs)}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        '';

      # Every command gets $REPO_ROOT, and it must name THIS repo no matter what
      # directory the caller was standing in when they typed the command.
      #
      # The obvious `git rev-parse --show-toplevel 2>/dev/null || pwd` does NOT
      # do that, and shipping it was a real bug, reproduced rather than
      # theorised: the git call runs in the CALLER's cwd, and
      # `nix run /path/to/dc-shield#<verb>` -- the form CI and a cold agent use
      # -- runs wherever they happen to be. From an unrelated directory
      # dev-lint then reported 5 findings on a stranger's files instead of this
      # repo's 43, dev-test collected the stranger's tests and printed a
      # cheerful "1 passed" while these 141 never ran, and dev-fmt REWROTE that
      # stranger's Python.
      #
      # So the anchor is ${self}: this flake's own source, resolved by Nix at
      # evaluation time, immutable, and independent of cwd by construction.
      #
      # The live work tree is preferred over that store copy when -- and only
      # when -- the caller really is inside a checkout of this same source,
      # because that is the case where writes have to land in real files rather
      # than in the read-only store. Identity is settled by comparing flake.nix
      # byte for byte: the `description` at the top of this file is unique per
      # repo, so no sibling repo in the fleet can impersonate this one. (They
      # share flake.lock verbatim, which is exactly why the lock would be a
      # useless fingerprint.) The comparison is bash's own $(< ...) rather than
      # cmp or diff so that it needs nothing on PATH.
      #
      # An inherited $REPO_ROOT wins over both. That is the documented escape
      # hatch for the case neither rule covers --
      # `REPO_ROOT=~/src/dc-shield nix run github:caesarakalaeii/dc-shield#fmt`
      # -- and it is also what lets the dev shell resolve the root once and hand
      # it down to every dev-* it spawns.
      rootPreamble = ''
        if [ -z "''${REPO_ROOT:-}" ]; then
          REPO_ROOT="${self}"
          _dev_tree="$(git rev-parse --show-toplevel 2>/dev/null || true)"
          if [ -n "$_dev_tree" ] && [ -f "$_dev_tree/flake.nix" ] &&
            [ "$(<"$_dev_tree/flake.nix")" = "$(<"${self}/flake.nix")" ]; then
            REPO_ROOT="$_dev_tree"
          fi
          unset _dev_tree
        fi
        export REPO_ROOT
      '';

      # Interpolated into every wrapper, called by the verbs that WRITE inside
      # the tree (setup, test, fmt, run). When REPO_ROOT resolved to the
      # immutable ${self} copy -- `nix run` by URL from outside any checkout --
      # there is nothing writable to act on. Letting the tool discover that for
      # itself yields a bare EACCES from somewhere inside black or coverage,
      # which a caller then has to reverse-engineer; fail here instead, before a
      # single file is touched, and name both ways out.
      #
      # The read-only verb (lint) deliberately does NOT call this: linting the
      # store copy from an arbitrary cwd is precisely the CI behaviour we want,
      # and it reports the same findings as the work tree because that copy IS
      # the tracked tree.
      #
      # Written as an `if` rather than `[ -w ... ] && return 0`, because under
      # `set -o errexit` a failing && list at function scope kills the wrapper
      # with a silent exit 1 before it can print anything.
      workTreeGuard = ''
        require_work_tree() {
          if [ -w "$REPO_ROOT" ]; then
            return 0
          fi
          echo "REPO_ROOT is $REPO_ROOT," >&2
          echo "this flake's read-only source rather than a work tree -- and this command writes." >&2
          echo "Run it from inside a dc-shield checkout, or pass REPO_ROOT=/path/to/dc-shield." >&2
          exit 1
        }
      '';

      # One derivation per command, reused by both `apps` and the dev shell, so
      # the two can never diverge. `dev-` prefixed because a bare `test` binary
      # earlier on PATH would shadow the POSIX shell builtin and quietly break
      # every script in the repo that uses it.
      wrappers =
        pkgs:
        lib.mapAttrs (
          name: cmd:
          pkgs.writeShellApplication {
            name = "dev-${name}";
            runtimeInputs = toolchain pkgs;
            runtimeEnv = envVars pkgs;
            meta.description = cmd.description;
            text = ''
              ${rootPreamble}
              ${workTreeGuard}
              ${ldPreamble pkgs}
              ${cmd.text}
            '';
          }
        ) (commands pkgs);

      helpFor =
        pkgs:
        let
          cmds = commands pkgs;
          names = lib.attrNames cmds;
          width = lib.foldl' (a: n: lib.max a (builtins.stringLength n)) 0 names;
          pad = n: n + lib.concatStrings (lib.genList (_: " ") (width - builtins.stringLength n));
          line = n: c: "  dev-${pad n}  ${c.description}";
        in
        pkgs.writeShellApplication {
          name = "dev-help";
          meta.description = "print this repo's command map (works offline)";
          text = ''
            cat <<'EOF'
            ${lib.concatStringsSep "\n" (lib.mapAttrsToList line cmds)}
            EOF
          '';
        };
    in
    {
      # `nix flake show` -- the discovery entrypoint, and deliberately the whole
      # machine-facing contract: every app carries a meta.description, which
      # `nix flake show` prints inline and `nix flake show --json` exposes at
      # .apps.<system>.<name>.description. Pure evaluation, so an agent gets the
      # entire command map in one cheap call without reading a README.
      #
      # Do NOT invent a top-level output for this (`agentManifest` and friends).
      # Nix answers `warning: unknown flake output '<name>'` on every single
      # `nix flake check`, forever.
      apps = forAllSystems (
        pkgs:
        lib.mapAttrs (name: cmd: {
          type = "app";
          program = "${(wrappers pkgs).${name}}/bin/dev-${name}";
          meta.description = cmd.description;
        }) (commands pkgs)
      );

      # `nix develop` -- the toolchain, plus a dev-<verb> for every app.
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = toolchain pkgs ++ lib.attrValues (wrappers pkgs) ++ [ (helpFor pkgs) ];

          env = envVars pkgs;

          # Some C extensions and node-gyp addons compile at -O0, where glibc's
          # _FORTIFY_SOURCE becomes a hard error instead of a warning.
          hardeningDisable = [ "fortify" ];

          shellHook = ''
            # mkShell inherits SOURCE_DATE_EPOCH=315532800 (1980-01-01) from
            # stdenv, and any wheel or zip built in here then dies with "ZIP does
            # not support timestamps before 1980".
            unset SOURCE_DATE_EPOCH

            ${rootPreamble}
            ${ldPreamble pkgs}

            # Nothing networked, nothing stateful and nothing interactive above
            # this line, and nothing below it either. No venv creation, no
            # `pip install`, no config.json scaffolding, no `read`, no
            # `exec $SHELL`. Bootstrapping in the hook makes a cold
            # `nix develop -c pytest` do work before it runs anything, on EVERY
            # -c invocation -- the exact failure an unattended agent cannot
            # diagnose.

            # The banner is interactive-only, and this guard is load-bearing:
            # shellHook output lands on the STDOUT of `nix develop -c <cmd>`, so
            # an unguarded echo corrupts anything parsing it
            # (`nix develop -c cat x.json | jq` fails to parse). $- is the only
            # reliable discriminator -- it lacks `i` under `nix develop -c` and
            # has it at an interactive prompt. Do not test $PS1 (unset in both)
            # or $IN_NIX_SHELL (set in both). [ -t 1 ] is NOT sufficient: it
            # still leaks the banner when the caller allocates a pty, which is
            # what agent harnesses do. >&2 is the second layer.
            case $- in
              *i*) echo "dc-shield dev shell -- 'dev-help' for the command map" >&2 ;;
            esac
          '';
        };
      });

      # `nix flake check` -- honest by construction. It realises the toolchain
      # closure (so a typo'd or currently-broken attr fails here) and builds
      # every wrapper, which runs shellcheck over every command text. NEVER add
      # a check that always passes: an agent reads "all checks passed!" as a
      # signal, and a fake check makes `nix flake check` a liar.
      checks = forAllSystems (pkgs: {
        toolchain =
          pkgs.runCommand "toolchain-check"
            {
              nativeBuildInputs = toolchain pkgs ++ lib.attrValues (wrappers pkgs);
            }
            ''
              for verb in ${lib.escapeShellArgs (lib.attrNames (commands pkgs))}; do
                command -v "dev-$verb" > /dev/null || {
                  echo "dev-$verb is not on PATH" >&2
                  exit 1
                }
              done
              touch "$out"
            '';
      });

      # `nix fmt` -- formats the *Nix* in this repo; project code is `dev-fmt`.
      # nixfmt-tree (the treefmt wrapper) rather than bare nixfmt, because bare
      # nixfmt tries to parse every path handed to it and fails on non-Nix files.
      # This file ships already formatted, so `nix fmt` is a no-op rather than a
      # diff.
      formatter = forAllSystems (pkgs: pkgs.nixfmt-tree);
    };
}

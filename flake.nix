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
    # would otherwise fail with "called with unexpected argument 'self'".
    { nixpkgs, ... }:
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
              # ip_locator and asn_lookup anchor their cache to
              # os.path.dirname(__file__), i.e. $REPO_ROOT/ipdb (already
              # gitignored), so this is cwd-independent -- but the modules are
              # top-level, so they only import with the repo root on the path.
              #
              # Passing the stdlib `logging` module itself as the logger is not a
              # hack for its own sake: both loaders reach for l.info/l.error and
              # their module-level `l` defaults to None, so a plain
              # `_load_db()` dies with AttributeError. The module exposes exactly
              # the two functions they call.
              #
              # Re-running this is cheap and safe: the loaders re-download only
              # when the cached CSVs are stale.
              PYTHONPATH="$REPO_ROOT''${PYTHONPATH:+:$PYTHONPATH}" \
                "${py}" -c 'import logging, ip_locator, asn_lookup; logging.basicConfig(level=logging.INFO, format="%(message)s"); ip_locator.set_logger(logging); asn_lookup.set_logger(logging); ip_locator._load_db(); asn_lookup._load_db()' "$@"
            '';
          };
          test = {
            description = "run the pytest suite (offline; integration tests deselected by pytest.ini)";
            # Deliberately no `cd "$REPO_ROOT"`. pytest finds pytest.ini by
            # walking up from its arguments, so the suite runs correctly from a
            # subdirectory anyway, and cd'ing would break the far more common
            # `dev-test tests/test_smoke.py` with a relative path.
            text = ''"${py}" -m pytest "$@"'';
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
              if [ "$#" -eq 0 ]; then set -- "$REPO_ROOT"; fi
              "${black}" "$@"
            '';
          };
          run = {
            description = "(network on first start) serve the Quart/Hypercorn honeypot on 0.0.0.0; run `setup` first to avoid a ~60s DB download";
            text = ''
              # main.py resolves $CONFIG_PATH against the process cwd and defaults
              # it to a bare "config.json", so an unanchored launch from a
              # subdirectory silently misses the config and falls through to the
              # get_env_vars() path -- serving a different site with no error. A
              # caller-supplied CONFIG_PATH still wins.
              #
              # config.json is gitignored and absent from a fresh clone; copy
              # config/config_template.json to it first (app_port lives there).
              export CONFIG_PATH="''${CONFIG_PATH:-$REPO_ROOT/config.json}"

              # This is the ONE command that cds, and only because main.py builds
              # its Logger with the cwd-relative path "logs/log1.txt". Without the
              # cd, launching from a subdirectory scatters half-written logs/
              # directories through the work tree, and only the root one is
              # gitignored. Safe here in a way it would not be for test/lint/fmt:
              # the server takes no path arguments to resolve against the caller.
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

      # Every command gets $REPO_ROOT. `nix run` and `nix develop` both start in
      # whatever directory they were invoked from, so a bare relative path
      # silently forks a second environment as soon as an agent works from a
      # subdirectory. Note we do NOT cd there: commands act on the caller's cwd
      # on purpose.
      rootPreamble = ''
        REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
        export REPO_ROOT
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

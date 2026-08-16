{
  # Keep this line accurate and one line long: `nix flake metadata` prints it,
  # and it is the first thing a cold agent learns about the repo.
  description = "dc-shield -- educational Quart/Hypercorn honeypot demonstrating Discord geoblocking and browser fingerprinting. Run `nix flake show` for the command map.";

  # nixpkgs is the only input, on purpose.
  #
  # flake-utils would buy exactly one thing here -- eachDefaultSystem -- which
  # the canonical block below already provides as one line of genAttrs. In
  # exchange it costs a second lock node in every repo (measured:
  # `nix flake metadata github:numtide/flake-utils` locks nodes `root` and
  # `systems`), a second upstream that can break one repo and not the others,
  # and a hardcoded system list this repo cannot edit. Measured today, that
  # list is `aarch64-darwin aarch64-linux x86_64-darwin x86_64-linux` -- it
  # still carries x86_64-darwin, which throws on this nixpkgs (see `systems`
  # in the block below).
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    # `...` rather than a closed argument set, so that adding a second input
    # later does not abort at eval. Measured with a throwaway flake declaring
    # `outputs = { nixpkgs }:`, which nix rejects with
    #   error: function 'outputs' called with unexpected argument 'self'
    #
    # `self` is bound rather than swallowed by the `...` because the canonical
    # block anchors every command on it: a flake that leaves it out and reaches
    # for it anyway dies with `error: undefined variable 'self'` (measured the
    # same way). See rootPreamble in the block below.
    { self, nixpkgs, ... }:
    let
      lib = nixpkgs.lib;

      # ======================================================================
      # PER-REPO BLOCK 5 -- the name in the interactive banner
      # ======================================================================
      # Cosmetic, but it is how a human tells two open dev shells apart.
      repoName = "dc-shield";

      # ======================================================================
      # PER-REPO BLOCK 1 -- the toolchain
      # ======================================================================
      # Every runtime and test dependency in requirements.txt has a python313
      # attr in this nixpkgs -- with one exception, `ipaddress`, which needs no
      # attr and is explained below -- so the interpreter is built with them and
      # this repo needs no dependency bootstrap and no network to test: a cold
      # `nix develop -c dev-test` runs the suite offline. Measured on this
      # nixpkgs rev: 141 passed, 26 deselected.
      #
      # The consequence to internalise: there is no .venv and no pip in here. To
      # add a dependency, add it to requirements.txt (for Docker/CI) AND to this
      # list. Do not "fix" a missing package by creating a .venv beside this env
      # -- you then get two interpreters, and `dev-test` and a bare `pytest`
      # silently disagree about which one is live.
      #
      # python313 to match the Dockerfile (`FROM python:3.13-slim`), not CI's
      # '3.11': the image is what actually ships, and pinning by major rather
      # than the rolling `python3` alias keeps a nixpkgs bump from moving the
      # interpreter under an agent mid-task. Resolved here to 3.13.15.
      pythonEnv =
        pkgs:
        pkgs.python313.withPackages (ps: [
          # ---- runtime ----
          ps.quart
          ps.hypercorn
          ps.requests
          ps.user-agents
          # withVoice = false drops PyNaCl, libsodium, libopus, opusfile and
          # both ffmpeg builds from the closure. Measured against this rev with
          # `nix path-info -Sh` on the two otherwise identical envs:
          # 1.4 GiB with voice, 411.9 MiB without. Justified because nothing in
          # this repo touches Discord voice (grep for VoiceClient, FFmpegAudio,
          # voice_client and nacl across *.py returns nothing) -- it only posts
          # embeds and runs a slash-command bot. Re-enable it the day a voice
          # feature lands, and expect the closure to grow ~3.5x.
          (ps.discordpy.override { withVoice = false; })
          # requirements.txt also lists `ipaddress`. That PyPI distribution is
          # the Python 2 backport of the stdlib module, which is why there is no
          # python313Packages.ipaddress attr to add here (verified: `nix eval`
          # on it errors with "does not provide attribute").
          # ---- tests ----
          ps.pytest
          ps.pytest-asyncio # pytest.ini sets asyncio_mode = auto
          ps.pytest-cov # pytest.ini's addopts hard-require --cov
          ps.pytest-mock
          ps.httpx
          # ---- code quality (the tools CI's black and flake8 steps use) ----
          ps.black
          ps.flake8
          ps.mypy
        ]);

      toolchain = pkgs: [
        # ---- this repo's ecosystem ----
        (pythonEnv pkgs)
        # For poking the HTTP service `run` starts, from inside the shell.
        pkgs.curl

        # ---- general-purpose, called by no verb below ----
        # git is not decoration: $SRC_ROOT holds TRACKED files only, so
        # `git add` is what makes a new file visible to a verb run by URL.
        pkgs.git
        # `nix flake show --json` is the machine-readable command map.
        pkgs.jq
        # This tree has no Makefile today; make is on PATH for ad-hoc use.
        pkgs.gnumake
      ];

      # ======================================================================
      # PER-REPO BLOCK 2 -- libraries that get dlopened, not linked
      # ======================================================================
      # Empty on purpose, and this is the degenerate case the canonical block
      # supports: with an empty list it emits no LD_LIBRARY_PATH preamble at
      # all. LD_LIBRARY_PATH exists to rescue manylinux wheels, whose bundled
      # .so files are dlopened where neither patchelf nor the nix linker can see
      # them. Every dependency here is built by nixpkgs and already has its
      # RPATH, so there is nothing to rescue.
      nativeLibs = pkgs: [ ];

      # ======================================================================
      # PER-REPO BLOCK 3 -- constant environment variables
      # ======================================================================
      # Constants only. Anything that must READ an existing value
      # (LD_LIBRARY_PATH) or UNSET something (SOURCE_DATE_EPOCH) is the
      # canonical block's business, not this one's.
      #
      # Applied to BOTH surfaces -- the dev shell and every `nix run` wrapper --
      # so a command cannot behave differently depending on how it was invoked.
      envVars = pkgs: {
        # This repo's console logging is logger.py's Logger, whose every
        # console method writes with print(); main.py builds one at module
        # scope (`l = Logger(console_log=True, ...)`, main.py line 30). Block
        # buffered, that output is lost the moment an agent pipes
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
      # `build` is absent, and that absence is information: this repo produces
      # no local artifact. Its deliverable is the GHCR container image, built by
      # `docker build .` in .github/workflows/build_and_push.yml against a
      # daemon no flake can supply.
      #
      # `setup` exists but NOT to install dependencies -- the interpreter above
      # already carries all of them. It is here because `run` downloads GeoIP
      # and ASN CSVs on first start (four files, 47 MiB measured: 10.9 MB and
      # 20.2 MB of dbip-country, 13.8 MB and 4.5 MB of dbip-asn), and an agent
      # needs a way to pay that cost once, deliberately, rather than discovering
      # it as a silent stall. `setup` does NOT make `run` offline-capable:
      # main.py refetches the X4BNet VPN subnet list from raw.githubusercontent
      # on EVERY start (main.py line 1702 -> read_subnets_from_file, which has
      # no cache), which is why `run` is marked (network) unconditionally.
      #
      # Two notes on the anchoring the canonical block hands these texts, both
      # of which used to be argued inside the machinery region and belong here
      # instead, next to the verbs they are about:
      #
      #   * The anchor this repo carried before (see `git show HEAD~1:flake.nix`
      #     once this lands) resolved the tree with
      #     `git rev-parse --show-toplevel`, then compared flake.nix, and let an
      #     inherited $REPO_ROOT override both. The canonical one drops both
      #     halves: it walks up from $PWD comparing whole flake.nix files, so it
      #     needs neither git on PATH nor a .git directory, and no wrapper reads
      #     an ambient $REPO_ROOT -- which is what stops `nix run /path/to/B#fmt`
      #     from inside repo A's dev shell pointing B's formatter at A.
      #   * `need_writable_checkout` is offered by the block but not called by
      #     it; which verb writes is this section's knowledge. Here that is
      #     setup, test, run, and fmt in its no-argument form.
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
            description = "(network) prefetch the 47 MiB of GeoIP + ASN CSVs into ipdb/ so `run` starts fast";
            text = ''
              # Downloads into the tree, so it needs a real one.
              need_writable_checkout

              # ip_locator and asn_lookup both anchor their cache to
              # os.path.dirname(__file__), i.e. $REPO_ROOT/ipdb (`ipdb` is in
              # .gitignore), so this is cwd-independent -- but the modules are
              # top-level, so they only import with the repo root on the path.
              #
              # PYTHONSAFEPATH is the other half of that anchoring, and it is
              # not cosmetic: measured on this interpreter, `python -c` without
              # it reports sys.path[0] == "" (the process cwd) and PYTHONPATH
              # only at sys.path[1], so a stray ip_locator.py in the caller's
              # directory would be imported instead of this repo's and the
              # download would land wherever that file lives. With
              # PYTHONSAFEPATH=1, sys.flags.safe_path is True and cwd is gone
              # from the front of the path.
              #
              # Passing the stdlib `logging` module itself as the logger is not
              # a hack for its own sake: both loaders default their module-level
              # `l` to None and then call l.info (and asn_lookup also l.error),
              # so a plain `_load_db()` dies with AttributeError. Those two
              # names are exactly what the `logging` module exposes.
              #
              # Re-running this is cheap and safe: _file_is_stale() re-downloads
              # only when a CSV is missing or older than REFRESH_SECONDS
              # (7 days). No arguments are read.
              PYTHONSAFEPATH=1 PYTHONPATH="$REPO_ROOT''${PYTHONPATH:+:$PYTHONPATH}" \
                "${py}" -c 'import logging, ip_locator, asn_lookup; logging.basicConfig(level=logging.INFO, format="%(message)s"); ip_locator.set_logger(logging); asn_lookup.set_logger(logging); ip_locator._load_db(); asn_lookup._load_db()'
            '';
          };
          test = {
            description = "run the pytest suite (offline; integration tests deselected by pytest.ini)";
            text = ''
              # Writes .coverage, htmlcov/ and .pytest_cache, all cwd-relative.
              need_writable_checkout

              # This verb DOES cd, and every clause of that is load-bearing.
              # Measured by running this interpreter's `pytest` with no
              # arguments from a scratch directory holding one trivial test:
              #   * It collected the CALLER's test and reported "1 passed".
              #     Without the cd, `nix run <url>#test` from an unrelated
              #     directory would print that instead of running these 141.
              #     A false green.
              #   * `rootdir:` in that run was the scratch directory, so this
              #     repo's pytest.ini never applied: the header said
              #     `asyncio: mode=Mode.STRICT` (pytest.ini asks for auto) and
              #     no coverage was reported (its addopts carry --cov).
              #   * .coverage, htmlcov/ and .pytest_cache are written relative
              #     to cwd, and once they land outside the repo no .gitignore
              #     of ours covers them at all.
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
              # `ignore =` value, and flake8 >= 6 refuses to parse that. Run it
              # without --isolated from the repo root and it dies with:
              #   ValueError: Error code '#' supplied to 'ignore' option does
              #   not match '^[A-Z]{1,3}[0-9]{0,3}$'
              # requirements.txt asks for flake8>=6.1.0, so EVERY flake8 this
              # project can legally install crashes on its own config file, pip
              # and nix alike. CI survives it only because the flake8 step is
              # continue-on-error. So skip the file and restate its intent here.
              #
              # Do NOT "fix" this by deleting --isolated. Fix .flake8 in its own
              # commit, then delete these flags and let the file win again.
              #
              # The default target is the repo, never the caller's cwd -- a gate
              # that passes by inspecting a stranger's files is worse than no
              # gate. No cd and no need_writable_checkout here though: flake8
              # only reads, and pointing it at the read-only store copy of this
              # flake's source (what $REPO_ROOT resolves to when the command is
              # run by URL from outside a checkout) yields the same 43 findings
              # as the work tree does, because that copy IS the tracked tree.
              # The verbAnchoring check below is what keeps that honest.
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
            description = "reformat with black (REWRITES files; 13 of the 18 tracked .py files are not black-clean yet, so expect a large diff)";
            text = ''
              # black's own defaults on purpose: the repo ships neither a
              # pyproject.toml nor a setup.cfg, so this is exactly what CI's
              # `black --check --diff .` compares against. Note .flake8 sets
              # max-line-length = 127 while annotating its E501 entry "handled
              # by black" -- `black --help` reports line-length default 88, and
              # that disagreement is pre-existing.
              #
              # This verb REWRITES files, so its default target is the one thing
              # in the flake that must not be guessed: were cwd the default,
              # `nix run /path/to/dc-shield#fmt` from an unrelated directory
              # would reformat that directory's Python. Explicit arguments are
              # still honoured verbatim, still resolved against the caller's
              # cwd, and deliberately skip the guard -- a typed-out path is an
              # instruction, not a default. (Verified: from a foreign git repo,
              # `dev-fmt` alone refuses, while `dev-fmt /some/scratch/file.py`
              # reformats exactly that file and nothing else.)
              if [ "$#" -eq 0 ]; then
                need_writable_checkout
                set -- "$REPO_ROOT"
              fi
              "${black}" "$@"
            '';
          };
          run = {
            description = "(network) serve the Quart/Hypercorn honeypot on 0.0.0.0; run `setup` first to avoid the CSV download";
            text = ''
              # Writes logs/ into the tree, so it needs a real one.
              need_writable_checkout

              # main.py resolves $CONFIG_PATH against the process cwd and
              # defaults it to a bare "config.json"
              # (`os.getenv("CONFIG_PATH", "config.json")`), so an unanchored
              # launch from a subdirectory silently misses the config and falls
              # through to the environment-variable path -- serving a different
              # site with no error. A caller-supplied CONFIG_PATH still wins.
              #
              # config.json is gitignored and absent from a fresh clone; copy
              # config/config_template.json to it first (app_port lives there).
              export CONFIG_PATH="''${CONFIG_PATH:-$REPO_ROOT/config.json}"

              # cd, because main.py builds its Logger with the cwd-relative path
              # "logs/log1.txt" (main.py line 30). Without it, launching from
              # anywhere else scatters logs/ directories wherever the caller
              # stood, and this repo's ignore rule for them is `logs/*`, which
              # -- having a slash -- is anchored to the repo root. Cheaper here than
              # anywhere else: the server takes no path arguments to resolve
              # against the caller, so nothing about the cd can surprise them
              # (`test` pays a real price for it; `lint` and `fmt` do not cd).
              cd "$REPO_ROOT"
              exec "${py}" main.py "$@"
            '';
          };
        };

      # ======================================================================
      # PER-REPO BLOCK 6 -- checks beyond the two canonical ones
      # ======================================================================
      # The canonical `anchoring` check proves rootPreamble and guardPreamble
      # behave. It cannot prove that THIS repo's verbs call them, because it
      # knows nothing about which verb writes. This one does, using the repo's
      # read-only verb (lint) and its mutating verb (fmt).
      #
      # It deliberately does not assert dev-lint's exit code: that is 1 today
      # because the tree has 43 real findings, and it would flip to 0 the day
      # somebody fixes them, turning good news into a broken check.
      extraChecks = pkgs: {
        verbAnchoring =
          pkgs.runCommand "verb-anchoring-check"
            {
              nativeBuildInputs = lib.attrValues (wrappers pkgs);
            }
            ''
              set -euo pipefail

              # A decoy carrying the marker files a naive anchor would accept
              # for a Python repo, a flake.nix that differs from this one, and
              # one filename this repo does not contain.
              mkdir decoy
              cd decoy
              printf 'import os\nx  =1\n' > main.py
              printf 'import json\ny  =2\n' > sibling_only.py
              printf 'quart\nhypercorn\n' > requirements.txt
              printf '{\n  description = "a different repo";\n  outputs = _: { };\n}\n' > flake.nix
              cp -r . ../decoy.orig

              # Grep by NAME, not by directory: if the anchor wrongly landed on
              # the decoy, flake8 would be standing in it and would print bare
              # relative paths, so a grep for "decoy" would match nothing and
              # the leak would sail straight through. A filename this repo does
              # not contain is the thing that cannot be spelled both ways.
              dev-lint > lint.log 2>&1 || true
              if grep -q sibling_only lint.log; then
                echo "dev-lint graded the decoy" >&2
                cat lint.log >&2
                exit 1
              fi
              # ...and it must have graded SOMETHING: a verb that read nothing
              # at all also passes the test above.
              if ! grep -q ${lib.escapeShellArg "${self}"} lint.log; then
                echo "dev-lint graded neither the decoy nor this repo" >&2
                cat lint.log >&2
                exit 1
              fi

              # Refusal, not silence.
              if dev-fmt > fmt.log 2>&1; then
                echo "dev-fmt succeeded in a foreign tree; it must refuse" >&2
                cat fmt.log >&2
                exit 1
              fi

              # `*.log`, and every log file here must match that pattern -- a
              # file named plainly `log` would not be excluded and would fail
              # this diff.
              diff -r --exclude='*.log' . ../decoy.orig
              touch "$out"
            '';
      };

      # >>>>> BEGIN CANONICAL MACHINERY v1 <<<<<
      # ======================================================================
      # Everything from the BEGIN sentinel above to the END sentinel on the last
      # line of this file is fleet-canonical text: the same bytes in every repo
      # that carries this flake style. That is a checkable claim, not a boast --
      #
      #   sed -n '/BEGIN CANONICAL MACHINERY v1/,$p' flake.nix | sha256sum
      #
      # prints the same digest in every repo, or one of them has been edited.
      # (`,$p`, not a range ending on the END sentinel: a range whose closing
      # pattern were spelled out here would terminate on this very comment.)
      # Nothing here names a repository, a language, a tool or a project file.
      # If you find such a name below, it is contamination: the fix is to move
      # it into the per-repo section above, never to special-case it here.
      #
      # This region READS exactly these names from the per-repo section:
      #   nixpkgs  self  lib  repoName  toolchain  nativeLibs  envVars
      #   commands  extraChecks
      # and DEFINES exactly these:
      #   systems  forAllSystems  ldPreamble  rootPreamble  guardPreamble
      #   wrappers  helpFor  anchorCheck
      # plus the four flake outputs apps / devShells / checks / formatter.
      # Anything else in scope is invisible to it. The types of those eight
      # inputs, and the shell variables this region exports into command texts,
      # are specified in INTERFACE.md, which travels with this block.
      #
      # To change behaviour here you change it in every repo at once and bump
      # the version in both sentinels. A local edit is a bug by construction:
      # the digest above stops matching, and -- because rootPreamble anchors on
      # flake.nix byte-identity -- an edited working tree also stops being
      # recognised by wrappers built from the previous revision.
      # ======================================================================

      # ---- systems policy: decided once for the whole fleet ----
      #
      # Read this list as "evaluated on three, built on one". That is what was
      # measured, and it is all it means:
      #   * `nix flake check --all-systems` passes, so every output attribute
      #     below EVALUATES on all three systems.
      #   * only x86_64-linux has ever been BUILT. The machine this was verified
      #     on has no aarch64 emulation -- no binfmt handler, and `extra-
      #     platforms` is x86-only -- so aarch64 cannot be built there at all.
      # It is not a statement that anything works on aarch64. Do not upgrade it
      # into one in a README.
      #
      # Evaluating all three is still worth its seconds, because the failure it
      # catches is an eval-time failure: a `pkgs.<attr>` that exists on Linux
      # and not on darwin (`stdenv.cc.cc.lib` is the usual one) throws during
      # evaluation, and `nix flake check` without --all-systems checks only the
      # current system and sails straight past it.
      #
      # x86_64-darwin is deliberately absent. nixpkgs 26.11 replaced that whole
      # attribute set with a `throw`. genAttrs is lazy, so plain `nix develop`
      # on Linux would not notice -- it detonates later, on the --all-systems
      # run this policy requires. Add it back only against a separate
      # nixpkgs-26.05-darwin input.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      # Stand-in for flake-utils.lib.eachDefaultSystem. Passes `pkgs` rather
      # than a system string, because that is what every call site wants, and
      # keeps the system list in this file rather than in a second input's
      # hardcoded copy of it.
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # Prepend, never assign: a host LD_LIBRARY_PATH may be carrying something
      # the user needs, and clobbering it breaks binaries they launch from here.
      # Linux only -- on darwin the loader variable is DYLD_*, and exporting a
      # Linux-shaped value there is at best useless.
      #
      # `&&` short-circuits in Nix, so on darwin `nativeLibs pkgs` is never
      # forced. That is load-bearing for the systems policy above: it is what
      # lets a repo list Linux-only attrs in nativeLibs and still evaluate on
      # aarch64-darwin. Do not reorder the two operands.
      ldPreamble =
        pkgs:
        lib.optionalString (pkgs.stdenv.hostPlatform.isLinux && nativeLibs pkgs != [ ]) ''
          export LD_LIBRARY_PATH="${lib.makeLibraryPath (nativeLibs pkgs)}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        '';

      # Every command gets $SRC_ROOT and $REPO_ROOT. `nix run` and `nix develop`
      # both start in whatever directory they were invoked from, and no verb may
      # act on that directory -- these two are what it acts on instead.
      #
      # $SRC_ROOT is this flake's own source, snapshotted into the store when
      # the flake was evaluated. It is the one anchor that is always available:
      # `nix run /path/to/repo#lint` tells the running program nothing whatever
      # about /path/to/repo (flake refs are location-independent by design, and
      # there is no $FLAKE_DIR to read), so without `self` a wrapper invoked
      # that way has literally no way to name the repo it belongs to. Two
      # limitations worth knowing: it is read-only, being a store path, and in a
      # git checkout it contains only TRACKED files.
      #
      # $REPO_ROOT is the writable checkout when the caller is standing in one,
      # and $SRC_ROOT when they are not. Three things this deliberately is NOT:
      #
      #   * NOT `pwd`. A fallback to the caller's directory is how `fmt`
      #     rewrites a stranger's source tree and how `lint` prints "all checks
      #     passed" having read none of this repo.
      #   * NOT `git rev-parse --show-toplevel`. Run from inside some OTHER git
      #     repo it cheerfully answers with THAT repo's top level. It also needs
      #     git on PATH and a .git directory, so it fails on an export and in
      #     any wrapper whose toolchain omits git.
      #   * NOT an inherited $REPO_ROOT from the environment. The dev shell
      #     EXPORTS this variable, so honouring it would mean that running
      #     `nix run /path/to/B#fmt` from inside repo A's dev shell points B's
      #     formatter at A. An explicit path argument is how a caller overrides
      #     a verb's target; an ambient variable is how they do it by accident.
      #
      # Instead: walk up from $PWD and take the first ancestor that IS this
      # repo, proved by carrying a byte-identical flake.nix. A single tracked
      # filename, a marker directory, or a set of them is not proof -- sibling
      # repos in a fleet share those, and a decoy can be built to carry any list
      # of names you care to publish. The whole flake.nix is what distinguishes
      # repos, because description, toolchain and command map all differ, so the
      # whole flake.nix is what gets compared. Compared with bash's own
      # `$(<file)` rather than cmp or sha256sum, so the check depends on no
      # package at all -- pure builtins, correct even in a wrapper whose PATH
      # carries nothing but the repo's own toolchain.
      #
      # Consequence worth knowing: edit flake.nix and the dev-* wrappers in an
      # already-open `nix develop` stop recognising the tree, because they were
      # built from the previous flake.nix. That is a stale shell telling you so
      # -- re-enter it. `nix run` re-evaluates every time and never sees this.
      rootPreamble = ''
        SRC_ROOT=${lib.escapeShellArg "${self}"}
        export SRC_ROOT

        _dev_find_root() {
          local dir ref
          ref=$(<"$SRC_ROOT/flake.nix") || return 1
          dir=$(
            unset CDPATH
            cd -P -- "''${1:-.}" 2>/dev/null && pwd
          ) || return 1
          while [ -n "$dir" ]; do
            if [ -f "$dir/flake.nix" ] && [ "$(<"$dir/flake.nix")" = "$ref" ]; then
              printf '%s\n' "$dir"
              return 0
            fi
            dir=''${dir%/*}
          done
          return 1
        }

        REPO_ROOT="$(_dev_find_root "$PWD" || printf '%s\n' "$SRC_ROOT")"
        export REPO_ROOT
      '';

      # Wrappers only, not the shellHook -- an interactive shell has no business
      # carrying this function around. Any command text that writes files calls
      # it first, and it is the reason a mutating verb can fail loudly instead
      # of falling back to "well, the cwd then".
      #
      # The test is $REPO_ROOT != $SRC_ROOT, i.e. "rootPreamble found a real
      # checkout", not a permission or a store-path-prefix test. Both of those
      # answer a narrower question: a checkout may be read-only for unrelated
      # reasons, and a store path is not the only tree we must refuse to write.
      guardPreamble = ''
        need_writable_checkout() {
          if [ "$REPO_ROOT" != "$SRC_ROOT" ]; then
            return 0
          fi
          echo "''${0##*/}: this command rewrites files, so it needs a writable" >&2
          echo "checkout of this repo -- and standing in $PWD there is none: no" >&2
          echo "parent directory carries this flake's flake.nix. The only tree in" >&2
          echo "reach is the read-only store snapshot $SRC_ROOT, and rewriting" >&2
          echo "$PWD instead is exactly the bug this guard exists to prevent." >&2
          echo "cd into the repo (or \`nix develop\` it), or pass an explicit path." >&2
          exit 1
        }
      '';

      # One derivation per command, reused by both `apps` and the dev shell, so
      # the two can never diverge. `dev-` prefixed because a bare `test` binary
      # earlier on PATH would shadow the POSIX shell builtin and quietly break
      # every script in the repo that uses it.
      #
      # writeShellApplication, not writeShellScriptBin: it runs shellcheck at
      # BUILD time and sets `set -euo pipefail`, so an unquoted $@ or a silently
      # ignored failure is a `nix flake check` failure rather than a surprise in
      # front of an agent.
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
              ${guardPreamble}
              ${ldPreamble pkgs}
              ${cmd.text}
            '';
          }
        ) (commands pkgs);

      # `dev-help` is generated from the same attrset as everything else, so it
      # cannot describe a verb that does not exist or miss one that does. No
      # runtimeInputs: printing the map must work with nothing installed.
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

      # The regression gate for rootPreamble and guardPreamble, which are the
      # two pieces of this flake that can silently damage a tree that is not
      # this repo. It tests the MECHANISM, not any verb, which is precisely what
      # makes it fleet-generic: it needs to know nothing about what this repo
      # does, only that the anchor resolves and the guard refuses.
      #
      # The decoy is a real directory carrying a real flake.nix that differs.
      # Marker-file anchors pass a decoy like this -- that is the whole point of
      # the probe -- and so does any anchor that trusts `pwd`. Probe 2 is the
      # other half, and without it a guard that refused everything would score a
      # perfect pass: a tree that IS byte-identical must still be adopted, or
      # every mutating verb in the repo is dead. Probe 3 pins the subdirectory
      # case, which is the normal one for an agent working inside a repo.
      #
      # A per-repo probe that drives the actual verbs is strictly better and
      # cannot live here -- it has to know which verb writes and which needs a
      # network. INTERFACE.md shows how to add one via `extraChecks`.
      anchorCheck =
        pkgs:
        pkgs.runCommand "anchor-check" { } ''
          set -euo pipefail

          # The two preambles under test, verbatim, in a file the probes source.
          # A quoted heredoc, so every $ below is the bash the wrappers see.
          cat > preamble.sh <<'CANONICAL_PREAMBLE_EOF'
          ${rootPreamble}
          ${guardPreamble}
          CANONICAL_PREAMBLE_EOF

          mkdir decoy
          printf '{\n  description = "a different repo";\n  outputs = _: { };\n}\n' > decoy/flake.nix
          printf 'do not touch me\n' > decoy/victim.txt
          cp -r decoy decoy.orig

          # ---- probe 1: a foreign tree must not be adopted ----
          if ! ( cd decoy && . ../preamble.sh && [ "$REPO_ROOT" = "$SRC_ROOT" ] ); then
            echo "anchor adopted a directory that is not this repo" >&2
            exit 1
          fi
          # In a subshell: need_writable_checkout ends in `exit`, which would
          # otherwise take this whole build down instead of failing a condition.
          if ( cd decoy && . ../preamble.sh && need_writable_checkout ) > guard.log 2>&1; then
            echo "need_writable_checkout accepted a tree that is not this repo" >&2
            exit 1
          fi
          if ! diff -r decoy decoy.orig; then
            echo "the probes modified the foreign tree" >&2
            exit 1
          fi

          # ---- probe 2: a byte-identical checkout must be adopted ----
          cp -r ${lib.escapeShellArg "${self}"} checkout
          chmod -R u+w checkout
          if ! ( cd checkout && . ../preamble.sh &&
                 [ "$REPO_ROOT" = "$(pwd -P)" ] && need_writable_checkout ); then
            echo "anchor refused a byte-identical checkout of this repo" >&2
            exit 1
          fi

          # ---- probe 3: from a subdirectory, still the checkout root ----
          mkdir -p checkout/probe3/deeper
          if ! ( cd checkout/probe3/deeper && . ../../../preamble.sh &&
                 [ "$REPO_ROOT" = "$(cd -P ../.. && pwd)" ] ); then
            echo "anchor did not walk up to the checkout root from a subdirectory" >&2
            exit 1
          fi

          touch "$out"
        '';
    in
    {
      # `nix flake show` -- the discovery entrypoint, and deliberately the whole
      # machine-facing contract: every app carries a meta.description, which
      # `nix flake show` prints inline and `nix flake show --json` exposes at
      # .apps.<system>.<name>.description. Pure evaluation, so an agent gets the
      # entire command map in one cheap call without reading a README.
      #
      # Do NOT invent a top-level output for this (`agentManifest`, `probeThing`
      # ...). Nix answers with `warning: unknown flake output '<name>'` on every
      # single `nix flake check`, forever.
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

          # Natively-compiled extension modules are routinely built at -O0,
          # where glibc's _FORTIFY_SOURCE stops being a warning and becomes a
          # hard error.
          hardeningDisable = [ "fortify" ];

          shellHook = ''
            # mkShell inherits SOURCE_DATE_EPOCH=315532800 (1980-01-01) from
            # stdenv, and any wheel or zip built in here then dies with "ZIP does
            # not support timestamps before 1980".
            unset SOURCE_DATE_EPOCH

            # $REPO_ROOT and $SRC_ROOT are exported here as a convenience for
            # the human at the prompt. Every wrapper re-resolves them from
            # scratch and none of them reads these, on purpose: a stale value
            # exported by one repo's shell must never steer another repo's verb.
            ${rootPreamble}
            ${ldPreamble pkgs}

            # Nothing networked, nothing stateful and nothing interactive above
            # this line, and nothing below it either. No environment
            # bootstrapping, no dependency installation, no `read`, no
            # `exec $SHELL`. Bootstrapping in the hook makes a cold
            # `nix develop -c <anything>` start downloading before it runs
            # anything, on EVERY invocation -- the exact failure an unattended
            # agent cannot diagnose. That is what a `setup` verb is for.

            # The banner is interactive-only, and this guard is load-bearing:
            # shellHook output lands on the STDOUT of `nix develop -c <cmd>`, so
            # an unguarded echo corrupts anything parsing it
            # (`nix develop -c cat x.json | jq` fails to parse). $- is the only
            # reliable discriminator here -- it lacks `i` for `nix develop -c`
            # and has it at an interactive prompt. Do not test $PS1 (unset in
            # both) or $IN_NIX_SHELL (set in both). >&2 is the second layer, for
            # the case where a caller runs us on a pty.
            case $- in
              *i*) echo "${repoName} dev shell -- 'dev-help' for the command map" >&2 ;;
            esac
          '';
        };
      });

      # `nix flake check` -- honest by construction, and the only gate this
      # style has. `toolchain` realises the whole toolchain closure (so a typo'd
      # or currently-broken attr fails here, not halfway through a task) and
      # builds every wrapper, which runs shellcheck over every command text.
      # `anchoring` is the regression test described above.
      #
      # Repo-specific checks go in `extraChecks`, never here. They may not
      # shadow either canonical name: silently replacing `anchoring` with
      # something weaker is the exact failure this whole file exists to make
      # impossible, so a collision is an eval error with both names in it.
      #
      # NEVER add a check that always passes. An agent reads "all checks
      # passed!" as a signal, and a fake check makes `nix flake check` a liar.
      checks = forAllSystems (
        pkgs:
        let
          canonical = {
            toolchain =
              pkgs.runCommand "toolchain-check"
                {
                  nativeBuildInputs = toolchain pkgs ++ lib.attrValues (wrappers pkgs) ++ [ (helpFor pkgs) ];
                }
                ''
                  set -euo pipefail
                  dev-help > help.txt

                  # A while-read over a heredoc rather than `for x in <list>`,
                  # which is a bash syntax error when the list is empty -- and a
                  # repo with no verbs yet is a legitimate state.
                  while IFS= read -r verb; do
                    [ -n "$verb" ] || continue
                    command -v "dev-$verb" > /dev/null || {
                      echo "dev-$verb is not on PATH" >&2
                      exit 1
                    }
                    grep -q -- "dev-$verb" help.txt || {
                      echo "dev-$verb is missing from the dev-help map" >&2
                      exit 1
                    }
                  done <<'CANONICAL_VERBS_EOF'
                  ${lib.concatStringsSep "\n" (lib.attrNames (commands pkgs))}
                  CANONICAL_VERBS_EOF

                  touch "$out"
                '';
            anchoring = anchorCheck pkgs;
          };
          extra = extraChecks pkgs;
          clash = lib.intersectLists (lib.attrNames canonical) (lib.attrNames extra);
        in
        if clash != [ ] then
          throw "extraChecks must not redefine canonical checks: ${lib.concatStringsSep ", " clash}"
        else
          canonical // extra
      );

      # `nix fmt` -- formats the *Nix* in this repo; project code gets a `fmt`
      # verb. nixfmt-tree (the treefmt wrapper) rather than bare nixfmt, because
      # bare nixfmt tries to parse every path handed to it and fails on non-Nix
      # files. This file ships already formatted, so `nix fmt` is a no-op rather
      # than a diff across the fleet.
      #
      # This is the one verb here NOT anchored to $REPO_ROOT, and it cannot be:
      # `nix fmt` is nix's own verb, and nix -- not this flake -- decides which
      # paths the formatter receives, passing the cwd when the user names none.
      # A wrapper that overrode them would break `nix fmt path/to/one/file.nix`,
      # and it cannot tell that "." apart from the default. So `nix fmt` formats
      # where you stand, by design; the `fmt` verb is the anchored one.
      formatter = forAllSystems (pkgs: pkgs.nixfmt-tree);
    };
}
# >>>>> END CANONICAL MACHINERY v1 <<<<<

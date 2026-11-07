# ESP32PTPL2Follower regression tests

The regression suite has host tests, which compile the real firmware sources into
Windows executables, and optional firmware policy builds made with ESP-IDF. Both
cover the ESP32-P4 (Waveshare ESP32-P4-ETH) and the ESP32-S31 (Espressif
ESP32-S31-Function-CoreBoard-1). Hardware, Ethernet driver and on-device timing
behavior are not tested here.

## Windows setup

Install:

- **Node.js 18 or later** to run [run_all.js](run_all.js).
- **Python 3.9 or later** to run the Python test runners.
- **Visual Studio 2022** with the **Desktop development with C++** workload,
  including the MSVC x64/x86 build tools and a Windows SDK.

You do not need to open a Developer Command Prompt first. The Python runners find
`vcvars64.bat` for Visual Studio 2022 (Community, Professional, Enterprise or
BuildTools) or locate the newest C++ installation through `vswhere.exe`. If
neither is found, they use an already loaded x64 developer environment. When
the installed ESP Clang includes an x86-64 backend, they use that compiler
instead; otherwise they use `cl.exe`.

The firmware policy builds (`--profile`) also need **ESP-IDF v6.1**.
[build.py](../tools/build.py) finds the installation through the Espressif
Installation Manager, so an ESP-IDF shell is recommended but not required. The
ESP32-S31 is a preview target in ESP-IDF v6.1; the build helper adds
`--preview` for it automatically.

## Run the regression suite

Run from `.\tests`:

```cmd
node .\run_all.js C:\Temp\ESP32PTPL2Follower-regression
```

In this example, `C:\Temp\ESP32PTPL2Follower-regression` is where the results are
stored, in a file named `results.txt`.

Optional arguments:

| Argument                                   | Purpose                                                                                                                             |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| `--profile <pre_v3\|v3_0\|v3_1\|s31\|all>` | Also builds the firmware for each PTP authentication policy using that board profile. Can be repeated; `all` selects every profile. |
| `--python <python-executable>`             | Python interpreter for the runners. The default is the `PYTHON` environment variable, then `python`.                                |
| `--overwrite`                              | Replaces an existing `results.txt` without asking.                                                                                  |

Relative arguments are resolved from the directory where you run the command.
From the repository root, use `node .\tests\run_all.js` instead.

The output directory must be outside the source tree. It holds only the
combined log. Host-test executables are built in temporary directories that are
deleted afterwards. Firmware builds stay in the workspace, as
[build.py](../tools/build.py) requires, in `build_matrix_<profile>` with one
`<policy>.log` per build. The runner writes the stdout and stderr of every suite
to the log. The console shows suite progress, not live compiler output.

By default, the runner executes these suites:

| Suite                                                                                      | Script                                   |
| ------------------------------------------------------------------------------------------ | ---------------------------------------- |
| Core host tests                                                                            | [run_tests.py](run_tests.py)             |
| Clock owner host tests, run once as a simulated ESP32-P4 and once as a simulated ESP32-S31 | [run_clock_tests.py](run_clock_tests.py) |
| PTP authentication host tests                                                              | [run_auth_tests.py](run_auth_tests.py)   |

For each `--profile`, it also runs
[check_builds.py](../tools/check_builds.py), which builds three firmware images:
authentication disabled, optional (mixed) and required.

If the output directory already contains results, the runner asks before
replacing them, and the default answer is no. In a noninteractive run, pass
`--overwrite` to permit replacement. Declining leaves the existing log
untouched. Pressing Ctrl+C can leave a partial `results.txt`.

Example with firmware builds for the ESP32-S31 and one ESP32-P4 profile:

```cmd
node .\run_all.js C:\Temp\ESP32PTPL2Follower-regression --profile s31 --profile v3_1
```

Each profile adds three full ESP-IDF builds. The first build of a profile takes
several minutes.

## Results and exit status

After all suites finish, the runner scans the saved log:

- Each line starting with `PASS` counts as one pass. These are grouped results
  (a test scenario, an authentication case, a firmware build or a runner
  summary), not individual C++ checks.
- Each line starting with `FAIL` (including assertion failures such as
  `FAIL line 259: ...`) or `ERROR:` counts as one failure.

The runner adds one `FAIL:` line for a suite that fails without already
reporting a failure marker. A suite fails if it exits nonzero, cannot be
started, or reports no pass result. A zero exit code with failure markers is
also treated as a failure.

When one suite fails, the runner still runs the remaining suites. A failed suite
may stop early, however, so not every check may have run. The runner exits
nonzero if any suite fails. It returns `130` if interrupted while tests are
running, and `1` for a usage error or a declined overwrite.

To check the runner itself:

```cmd
node --test .\run_all_test.js
```

## Individual runs and coverage

Each runner can be run directly from the repository root or from `.\tests`, for
example `python tests\run_auth_tests.py`. `run_tests.py` accepts `--compiler`
and `--vcvars`; `run_auth_tests.py` accepts `--compiler <auto|esp-clang|msvc>`.

### Settings header fixtures

[ESP32PTPL2FollowerSettings.h](../main/ESP32PTPL2FollowerSettings.h) selects the board
wiring from the ESP-IDF target and stops with `#error` for any target other than
the ESP32-P4 or ESP32-S31. On the host, [clock_host/sdkconfig.h](clock_host/sdkconfig.h)
and [auth_host/sdkconfig.h](auth_host/sdkconfig.h) stand in for the generated
`sdkconfig.h`. They simulate the ESP32-P4 unless the runner defines
`CONFIG_IDF_TARGET_ESP32S31`.

The authentication policy macros in the settings header are wrapped in
`#ifndef` so that the runners and `build.py --define` can override them. Do not
remove those guards.

### Core host tests

[run_tests.py](run_tests.py) builds [core_tests.cpp](core_tests.cpp) with
[follower_core.cpp](../main/follower_core.cpp). It covers the PTP follower core,
measured Sync rate, MAC validation and collision detection, and TAI/UTC/local
time formatting and conversion. The Microsoft C runtime does not support full
POSIX TZ rules, so `UTC0` and `EST5EDT` run in separate processes. Rejection of
explicit DST rules is tested; newlib rule semantics need a POSIX or on-target
run.

### Clock owner host tests

[run_clock_tests.py](run_clock_tests.py) builds the real
[clock_owner.cpp](../main/clock_owner.cpp) with deterministic clock and mutex
stand-ins from [clock_host](clock_host). It runs these scenarios once per
simulated target (ESP32-P4 and ESP32-S31): lifecycle, metadata, snapshots,
steps, initialization and step failures, and preempted PHC/REALTIME bridge
reads (which must not unlock or cause a false `adjtime`). Clock behavior does not depend on
the target. Running both targets checks that the target-specific settings
compile and do not affect the clock.

### PTP authentication host tests

[run_auth_tests.py](run_auth_tests.py) compiles [auth_tests.cpp](auth_tests.cpp)
and the real [auth.cpp](../main/auth.cpp) once per case, 28 cases in all. It
generates a separate secrets header and HMAC reference vectors for each case.
Coverage:

- **Policies:** disabled, optional (mixed), required, and the header's own
  default policy, read from `ESP32PTPL2FollowerSettings.h`.
- **Invalid policy:** required while disabled.
- **Key ring faults:** empty, too many keys, duplicate IDs, zero ID, missing
  active key, short keys, punctuation and missing NUL terminator, each under
  both the mixed and required policies.
- **Key IDs:** boundary IDs and active-key rotation.
- **Missing secrets header:** handled as an empty key ring.

The host crypto layer ([auth_host](auth_host)) uses Windows BCrypt. The real
PSA crypto integration is checked only by the ESP-IDF firmware builds.

### Firmware PTP policy builds

[check_builds.py](../tools/check_builds.py) runs [build.py](../tools/build.py)
three times for one profile, overriding `FOLLOWER_PTP_AUTH_ENABLED` and
`FOLLOWER_PTP_AUTH_REQUIRED` with `--define`:

```cmd
python tools\check_builds.py --profile s31
```

These builds use your local `ESP32PTPL2FollowerSettingsSecrets.h`, so keep the build
outputs private. They show that the firmware compiles and links for each
policy. They do not show synchronization, signed-packet interoperability or
timing accuracy. The ESP32-S31 profile has been verified by building only; it
has not yet been tested on the ESP32-S31-Function-CoreBoard-1.

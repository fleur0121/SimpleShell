# 🐚 SimpleShell

A lightweight Unix-like shell built in C.  
SimpleShell supports foreground/background process execution, built-in commands, and a simple history feature.  
It’s designed to explore how shells manage processes, signals, and user input.

## ✨ Features

- Execute commands in **foreground** or **background** (`&`)
- Built-in commands: `cd`, `pwd`, `help`, `exit`
- **Command history** (up to 10 recent commands)
  - `history`, `!!`, `!n`
- Handles `SIGINT` (Ctrl+C) without exiting
- Uses `fork()`, `exec()`, and `waitpid()` for process management

## 🛠 Tech Stack

C · POSIX (fork / exec / waitpid) · CMake · clang

## ⚙️ Build & Run

```bash
git clone <YOUR_REPO_URL>
cd simpleshell
cmake -S . -B build
cmake --build build
./build/shell
```

#define _POSIX_C_SOURCE 200809L
#include "msgs.h"
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#define HISTORY_SIZE 10
#define BUFFER_SIZE 1024

typedef struct
{
    char *commands[HISTORY_SIZE];
    int count;
    int index;
} History;

void print_out(const char *format, const char *data)
{
    char buf[BUFFER_SIZE];
    int len = snprintf(buf, BUFFER_SIZE, format, data);
    if (len < 0)
    {
        _exit(1);
    }
    write(STDOUT_FILENO, buf, len);
}

void print_err(const char *format, const char *data)
{
    char buf[BUFFER_SIZE];
    int len = snprintf(buf, BUFFER_SIZE, format, data);
    if (len < 0)
    {
        _exit(1);
    }
    write(STDERR_FILENO, buf, len);
}

void handle_command(char *buffer, char **argv, bool *background)
{
    char *saveptr;
    char *token = strtok_r(buffer, " \n\t", &saveptr);
    int index = 0;
    *background = false;

    while (token)
    {
        if (!strcmp(token, "&"))
        {
            *background = true;
        }
        else
        {
            argv[index] = token;
            index++;
        }
        token = strtok_r(NULL, " \n\t", &saveptr);
    }
    argv[index] = NULL;
}

bool is_internal_command(char *command)
{
    return !strcmp(command, "exit") || !strcmp(command, "pwd") ||
           !strcmp(command, "cd") || !strcmp(command, "help") ||
           !strcmp(command, "history");
}

void add_history(const char *command, History *history)
{
    if (!command || !strlen(command) || command[0] == '\n')
    {
        return;
    }
    if (history->commands[history->index])
    {
        free(history->commands[history->index]);
    }
    int len = strlen(command);
    char *cpy = malloc(len + 1);

    if (cpy)
    {
        snprintf(cpy, len + 1, "%s", command);
        if (cpy[len - 1] == '\n')
        {
            cpy[len - 1] = '\0';
        }
        history->commands[history->index] = cpy;
        history->index = (history->index + 1) % HISTORY_SIZE;
        history->count++;
    }
    else
    {
        return;
    }
}

void print_history(History *history)
{
    int histories = history->count < HISTORY_SIZE ? history->count : HISTORY_SIZE;
    for (int i = histories - 1; i >= 0; i--)
    {
        int index = (history->index + HISTORY_SIZE - histories + i) % HISTORY_SIZE;
        char num[BUFFER_SIZE];
        sprintf(num, "%d", (history->count - histories + i));
        char buffer[BUFFER_SIZE];
        snprintf(buffer, BUFFER_SIZE, FORMAT_HISTORY("%s", "%s"), num,
                 history->commands[index]);
        print_out("%s", buffer);
    }
}

void run_internal_command(char **argv, bool *exit, char *prev_dir,
                          History *history)
{
    const char *command = argv[0];

    if (!strcmp(command, "exit"))
    {
        if (argv[1])
        {
            const char *msg = FORMAT_MSG("exit", TMA_MSG);
            print_err("%s", msg);
            return;
        }
        *exit = true;
        return;
    }
    else if (!strcmp(command, "pwd"))
    {
        if (argv[1])
        {
            const char *msg = FORMAT_MSG("pwd", TMA_MSG);
            print_err("%s", msg);
            return;
        }
        char buffer[BUFFER_SIZE];
        if (!getcwd(buffer, BUFFER_SIZE - 1))
        {
            const char *msg = FORMAT_MSG("pwd", GETCWD_ERROR_MSG);
            print_err("%s", msg);
            return;
        }
        // snprintf(buffer, BUFFER_SIZE, "%s\n", buffer);
        print_out("%s", buffer);
        write(STDOUT_FILENO, "\n", 1);
        return;
    }
    else if (!strcmp(command, "cd"))
    {
        if (argv[0] && argv[1] && argv[2])
        {
            const char *msg = FORMAT_MSG("cd", TMA_MSG);
            print_err("%s", msg);
            return;
        }

        char *dir = argv[1];
        char buffer[BUFFER_SIZE];
        char expanded_dir[BUFFER_SIZE];

        if (!dir || !strcmp(dir, "~"))
        {
            if (getcwd(buffer, BUFFER_SIZE))
            {
                snprintf(prev_dir, BUFFER_SIZE, "%s", buffer);
            }
            else
            {
                prev_dir[0] = '\0';
            }

            struct passwd *pw = getpwuid(getuid());
            if (!pw || chdir(pw->pw_dir) == -1)
            {
                const char *msg = FORMAT_MSG("cd", CHDIR_ERROR_MSG);
                print_err("%s", msg);
                return;
            }
            return;
        }

        if (!strcmp(dir, "-"))
        {
            if (prev_dir[0] == '\0' || chdir(prev_dir) == -1)
            {
                const char *msg = FORMAT_MSG("cd", CHDIR_ERROR_MSG);
                print_err("%s", msg);
                return;
            }
            return;
        }

        if (!getcwd(buffer, BUFFER_SIZE))
        {
            const char *msg = FORMAT_MSG("cd", GETCWD_ERROR_MSG);
            print_err("%s", msg);
            return;
        }

        if (dir[0] == '~')
        {
            struct passwd *pw = getpwuid(getuid());
            if (!pw)
            {
                const char *msg = FORMAT_MSG("cd", CHDIR_ERROR_MSG);
                print_err("%s", msg);
                return;
            }

            if (dir[1] == '/' || dir[1] == '\0')
            {
                snprintf(expanded_dir, BUFFER_SIZE, "%s%s", pw->pw_dir, dir + 1);
            }
            else
            {
                const char *msg = FORMAT_MSG("cd", CHDIR_ERROR_MSG);
                print_err("%s", msg);
                return;
            }
            dir = expanded_dir;
        }

        if (chdir(dir) == -1)
        {
            const char *msg = FORMAT_MSG("cd", CHDIR_ERROR_MSG);
            print_err("%s", msg);
            return;
        }

        snprintf(prev_dir, BUFFER_SIZE, "%s", buffer);
        return;
    }
    else if (!strcmp(command, "help"))
    {
        if (argv[1] && argv[2])
        {
            const char *msg = FORMAT_MSG("help", TMA_MSG);
            print_err("%s", msg);
            return;
        }

        const char *arg = argv[1];
        if (!arg)
        {
            const char *msg = FORMAT_MSG("exit", EXIT_HELP_MSG);
            print_out("%s", msg);
            msg = FORMAT_MSG("pwd", PWD_HELP_MSG);
            print_out("%s", msg);
            msg = FORMAT_MSG("cd", CD_HELP_MSG);
            print_out("%s", msg);
            msg = FORMAT_MSG("help", HELP_HELP_MSG);
            print_out("%s", msg);
            msg = FORMAT_MSG("history", HISTORY_HELP_MSG);
            print_out("%s", msg);
        }
        else if (!strcmp(arg, "exit"))
        {
            const char *msg = FORMAT_MSG("exit", EXIT_HELP_MSG);
            print_out("%s", msg);
        }
        else if (!strcmp(arg, "pwd"))
        {
            const char *msg = FORMAT_MSG("pwd", PWD_HELP_MSG);
            print_out("%s", msg);
        }
        else if (!strcmp(arg, "cd"))
        {
            const char *msg = FORMAT_MSG("cd", CD_HELP_MSG);
            print_out("%s", msg);
        }
        else if (!strcmp(arg, "help"))
        {
            const char *msg = FORMAT_MSG("help", HELP_HELP_MSG);
            print_out("%s", msg);
        }
        else if (!strcmp(arg, "history"))
        {
            const char *msg = FORMAT_MSG("history", HISTORY_HELP_MSG);
            print_out("%s", msg);
        }
        else
        {
            char msg[BUFFER_SIZE - strlen(arg) - 2];
            snprintf(msg, BUFFER_SIZE, "%s: %s\n", arg, EXTERN_HELP_MSG);
            print_out("%s", msg);
        }
        return;
    }
    else if (!strcmp(command, "history"))
    {
        print_history(history);
        return;
    }
    else
    {
        return;
    }
}

ssize_t read_command(char *buffer)
{
    ssize_t line_len = read(STDIN_FILENO, buffer, BUFFER_SIZE - 1);
    if (line_len == -1)
    {
        if (errno == EINTR)
        {
            return -2;
        }
        else
        {
            const char *msg = FORMAT_MSG("shell", READ_ERROR_MSG);
            print_err("%s", msg);
            return -1;
        }
    }
    buffer[line_len] = '\0';
    return line_len;
}

void prompt_directory(char *buffer)
{
    char dir[BUFFER_SIZE];
    if (!getcwd(buffer, BUFFER_SIZE - 2) || !getcwd(dir, BUFFER_SIZE - 2))
    {
        const char *msg = FORMAT_MSG("shell", GETCWD_ERROR_MSG);
        print_err("%s", msg);
    }
    else
    {
        snprintf(buffer, BUFFER_SIZE, "%s$ ", dir);
        print_out("%s", buffer);
    }
}

void run_command(char **argv, bool background)
{
    pid_t pid = fork();
    if (pid == -1)
    {
        const char *msg = FORMAT_MSG("shell", FORK_ERROR_MSG);
        print_err("%s", msg);
    }
    else if (pid == 0)
    {
        if (execvp(argv[0], argv) == -1)
        {
            const char *msg = FORMAT_MSG("shell", EXEC_ERROR_MSG);
            print_err("%s", msg);
            _exit(1);
        }
    }
    else
    {
        if (!background)
        {
            int status;
            if (waitpid(pid, &status, 0) == -1)
            {
                const char *msg = FORMAT_MSG("shell", WAIT_ERROR_MSG);
                print_err("%s", msg);
            }
        }
    }
}

void cleanup_zombies()
{
    while (waitpid(-1, NULL, WNOHANG) > 0)
    {
    }
}

void signal_handler(int sig)
{
    const char *msg = FORMAT_MSG("exit", EXIT_HELP_MSG);
    print_out("%s", msg);
    msg = FORMAT_MSG("pwd", PWD_HELP_MSG);
    print_out("%s", msg);
    msg = FORMAT_MSG("cd", CD_HELP_MSG);
    print_out("%s", msg);
    msg = FORMAT_MSG("help", HELP_HELP_MSG);
    print_out("%s", msg);
    msg = FORMAT_MSG("history", HISTORY_HELP_MSG);
    print_out("%s", msg);
    char buffer[BUFFER_SIZE];
    if (!getcwd(buffer, BUFFER_SIZE - 2))
    {
        const char *msg = FORMAT_MSG("shell", GETCWD_ERROR_MSG);
        print_err("%s", msg);
    }
    else
    {
        snprintf(buffer, BUFFER_SIZE, "%s$ ", buffer);
        print_out("%s", buffer);
    }

    signal(SIGINT, signal_handler);
}

bool handle_bang(char *command, char *buffer, const History *history)
{
    char clean_command[BUFFER_SIZE];
    snprintf(clean_command, BUFFER_SIZE, "%s", command);
    int len = strlen(clean_command);
    if (len > 0 && clean_command[len - 1] == '\n')
    {
        clean_command[len - 1] = '\0';
    }

    if (!strcmp(clean_command, "!!"))
    {
        if (history->count == 0)
        {
            const char *msg = FORMAT_MSG("history", HISTORY_NO_LAST_MSG);
            print_err("%s", msg);
            return false;
        }
        int last_index = (history->index + HISTORY_SIZE - 1) % HISTORY_SIZE;
        snprintf(buffer, BUFFER_SIZE, "%s", history->commands[last_index]);
        print_out("%s", buffer);
        write(STDOUT_FILENO, "\n", 1);
        return true;
    }

    if (isdigit(clean_command[1]))
    {
        int num = atoi(&clean_command[1]);
        int min_index =
            (history->count > HISTORY_SIZE) ? history->count - HISTORY_SIZE : 0;
        int max_index = history->count - 1;

        if (num < min_index || num > max_index)
        {
            const char *msg = FORMAT_MSG("history", HISTORY_INVALID_MSG);
            print_err("%s", msg);
            return false;
        }
        int position_back = history->count - 1 - num;
        int most_recent = (history->index - 1 + HISTORY_SIZE) % HISTORY_SIZE;
        int arr_index = (most_recent - position_back + HISTORY_SIZE) % HISTORY_SIZE;
        strcpy(buffer, history->commands[arr_index]);
        print_out("%s", buffer);
        write(STDOUT_FILENO, "\n", 1);
        return true;
    }
    const char *msg = FORMAT_MSG("history", HISTORY_INVALID_MSG);
    print_err("%s", msg);
    return false;
}

int main()
{
    char usr_input[BUFFER_SIZE];
    char *argv[100];
    bool background = false;
    bool exit = false;
    char prev_dir[BUFFER_SIZE] = {0};
    History history = {0};

    signal(SIGINT, signal_handler);

    while (!exit)
    {
        prompt_directory(usr_input);
        ssize_t read = read_command(usr_input);
        if (read == -1 || read == -2)
        {
            continue;
        }

        if (usr_input[0] == '!')
        {
            if (!handle_bang(usr_input, usr_input, &history))
            {
                continue;
            }
        }
        if (usr_input[0] != '!')
        {
            add_history(usr_input, &history);
        }

        handle_command(usr_input, argv, &background);

        if (argv[0] == NULL)
        {
            continue;
        }

        if (is_internal_command(argv[0]))
        {
            run_internal_command(argv, &exit, prev_dir, &history);
        }
        else
        {
            run_command(argv, background);
        }
        cleanup_zombies();
    }

    for (unsigned int i = 0; i < HISTORY_SIZE; i++)
    {
        if (history.commands[i])
        {
            free(history.commands[i]);
        }
    }
    return 0;
}

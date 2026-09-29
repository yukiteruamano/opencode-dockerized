#compdef opencode-dockerized
# shellcheck shell=bash disable=SC2034,SC2154,SC1087,SC2016

# Zsh completion for opencode-dockerized
# Source this file in your ~/.zshrc or place in /usr/local/share/zsh/site-functions/

_opencode_dockerized() {
    local -a commands
    commands=(
        'run:Run OpenCode in Docker (default: current directory)'
        'auth:Run OpenCode authentication (opencode auth login)'
        'models:List models available to the configured providers'
        'exec:Run a non-interactive prompt (opencode run)'
        'mcp:Manage MCP servers'
        'plugin:Manage plugins'
        'stats:Show usage statistics'
        'debug:Debugging and troubleshooting tools'
        'doctor:Diagnose install, guard, SSH/GPG, websearch, theme and env file'
        'install:First-time install / repair PATH, config, completions, aliases'
        'upgrade:Full upgrade from GitHub (git pull + sync + image rebuild)'
        'build:Build the Docker image'
        'update:Full upgrade from GitHub (git pull + sync + image rebuild)'
        'version:Show OpenCode version in the container'
        'config:Show, edit, or print config file path'
        'clean:Remove the Docker image'
        'help:Show help message'
    )

    _arguments -C \
        '1: :->cmds' \
        '*:: :->args'

    case $state in
        cmds)
            _describe -t commands 'opencode-dockerized command' commands
            ;;
        args)
            case $words[1] in
                run|models)
                    _files -/
                    ;;
                mcp)
                    _values 'mcp subcommand' list add auth logout
                    ;;
                plugin)
                    _values 'plugin subcommand' list add check update remove
                    ;;
                debug)
                    _values 'debug subcommand' paths config agents
                    ;;
                stats)
                    _arguments \
                        '--days[Show the last N days; 0 means today]:days:' \
                        '--year[Show a calendar year]:year:' \
                        '--all[Show lifetime statistics]' \
                        '--project[Filter by project ID, or "." for the current project]:project:' \
                        '--models[Show model usage]' \
                        '--tools[Show tool reliability]' \
                        '--cost[Show cost and token details]' \
                        '--full[Show every detailed section]' \
                        '--limit[Number of rows in detailed sections]:limit:' \
                        '--json[Output statistics as JSON]'
                    ;;
                config)
                    local -a config_cmds
                    config_cmds=(
                        'show:Show current configuration'
                        'edit:Edit wrapper config file in $EDITOR'
                        'path:Print wrapper config file path'
                        'sync:Refresh security layer from repo (--check for drift only)'
                        'opencode:Show or edit the OpenCode config (path|edit)'
                    )
                    _describe -t config_cmds 'config subcommand' config_cmds
                    ;;
                upgrade|update)
                    _values 'self-update flag' --check --yes --no-build
                    ;;
                install)
                    _values 'install flag' --yes --only
                    ;;
            esac
            ;;
    esac
}

compdef _opencode_dockerized opencode-dockerized
compdef _opencode_dockerized ocd

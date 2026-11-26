#include "cli/completion.hpp"

namespace kasumi::cli {

std::string generate_completion_script(CompletionShell shell) {
    switch (shell) {
        case CompletionShell::Bash:
            return R"bash(# Bash completion for kasumi
_kasumi_profiles() {
    command kasumi list 2>/dev/null
}

_kasumi() {
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local top_commands="status show logs start stop pause resume sync conflicts config web list diagnostics key profile daemon ignore fsck gc repack resolve-missing remote version help completion"
    local profile_cmds="create edit clone storage rename delete test"
    local daemon_cmds="run stop status sync pause resume unlock lock reload logs autostart"
    local autostart_cmds="install uninstall status"
    local ignore_cmds="check init"
    local conflicts_cmds="resolve"
    local gc_cmds="remove-writer remove-barrier"
    local remote_cmds="heads tree commits summary stat log commit get restore epochs epoch contents content markers objects orphans writers health"
    local shells="bash zsh fish powershell"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        if [[ ${cur} == -* ]]; then
            COMPREPLY=( $(compgen -W "-h --help -v --version --lang" -- "${cur}") )
        else
            COMPREPLY=( $(compgen -W "${top_commands}" -- "${cur}") )
        fi
        return 0
    fi

    if [[ ${prev} == "--lang" ]]; then
        COMPREPLY=( $(compgen -W "en pt-BR" -- "${cur}") )
        return 0
    fi

    if [[ ${prev} == "--key-storage" ]]; then
        COMPREPLY=( $(compgen -W "vault file memory" -- "${cur}") )
        return 0
    fi

    if [[ ${prev} == "--preset" ]]; then
        COMPREPLY=( $(compgen -W "default dev office minimal" -- "${cur}") )
        return 0
    fi

    if [[ ${prev} == "--watch" || ${prev} == "--paused" ]]; then
        COMPREPLY=( $(compgen -W "on off" -- "${cur}") )
        return 0
    fi

    local cmd="${COMP_WORDS[1]}"
    if [[ ${cmd} == "--lang" && ${COMP_CWORD} -ge 3 ]]; then
        cmd="${COMP_WORDS[3]}"
    fi

    case "${cmd}" in
        profile)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${profile_cmds}" -- "${cur}") )
            elif [[ ${COMP_CWORD} -eq 3 ]]; then
                case "${COMP_WORDS[2]}" in
                    edit|clone|storage|rename|delete|test)
                        COMPREPLY=( $(compgen -W "$(_kasumi_profiles)" -- "${cur}") )
                        ;;
                esac
            elif [[ ${COMP_CWORD} -eq 4 && "${COMP_WORDS[2]}" == "storage" ]]; then
                COMPREPLY=( $(compgen -W "vault file memory" -- "${cur}") )
            elif [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "--local --remote --key-storage --min-depth --min-age --bwlimit --clear-bwlimit --concurrency --clear-concurrency --rclone-config --clear-rclone-config --watch --clear-watch --sync-interval --clear-sync-interval --paused --verify --allow-empty-local --confirm --quiet --json --log-file --help" -- "${cur}") )
            fi
            ;;
        daemon)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${daemon_cmds}" -- "${cur}") )
            elif [[ ${COMP_CWORD} -eq 3 && ${cur} != -* ]]; then
                case "${COMP_WORDS[2]}" in
                    autostart)
                        COMPREPLY=( $(compgen -W "${autostart_cmds}" -- "${cur}") )
                        ;;
                    status|sync|pause|resume|unlock|lock|logs)
                        COMPREPLY=( $(compgen -W "$(_kasumi_profiles)" -- "${cur}") )
                        ;;
                esac
            elif [[ ${cur} == -* ]]; then
                case "${COMP_WORDS[2]}" in
                    run)
                        COMPREPLY=( $(compgen -W "--background --foreground --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    status)
                        COMPREPLY=( $(compgen -W "--full --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    sync)
                        COMPREPLY=( $(compgen -W "--wait --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    logs)
                        COMPREPLY=( $(compgen -W "--lines --follow -f --full --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    *)
                        COMPREPLY=( $(compgen -W "--quiet --json --log-file --help" -- "${cur}") )
                        ;;
                esac
            fi
            ;;
        ignore)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${ignore_cmds}" -- "${cur}") )
            elif [[ ${COMP_CWORD} -eq 3 ]]; then
                COMPREPLY=( $(compgen -W "$(_kasumi_profiles)" -- "${cur}") )
            elif [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "--preset --force --dry-run --quiet --json --log-file --help" -- "${cur}") )
            fi
            ;;
        gc)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${gc_cmds} $(_kasumi_profiles)" -- "${cur}") )
            elif [[ ${COMP_CWORD} -eq 3 && ( "${COMP_WORDS[2]}" == "remove-writer" || "${COMP_WORDS[2]}" == "remove-barrier" ) ]]; then
                COMPREPLY=( $(compgen -W "$(_kasumi_profiles)" -- "${cur}") )
            elif [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "--dry-run --min-age --bwlimit --concurrency --confirm-abandoned --quiet --json --log-file --help" -- "${cur}") )
            fi
            ;;
        remote)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${remote_cmds}" -- "${cur}") )
            elif [[ ${COMP_CWORD} -eq 3 ]]; then
                COMPREPLY=( $(compgen -W "$(_kasumi_profiles)" -- "${cur}") )
            elif [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "--head --commit --audit --dry-run --bwlimit --concurrency --full --quiet --json --log-file --help" -- "${cur}") )
            fi
            ;;
        conflicts)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${conflicts_cmds} $(_kasumi_profiles)" -- "${cur}") )
            elif [[ ${COMP_CWORD} -eq 3 && "${COMP_WORDS[2]}" == "resolve" ]]; then
                COMPREPLY=( $(compgen -W "$(_kasumi_profiles)" -- "${cur}") )
            elif [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "--keep-canonical --keep --dry-run --quiet --json --log-file --help" -- "${cur}") )
            fi
            ;;
        completion)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${shells}" -- "${cur}") )
            fi
            ;;
        show|diagnostics|key|sync|status|fsck|repack|resolve-missing|logs|start|stop|pause|resume)
            if [[ ${COMP_CWORD} -eq 2 && ${cur} != -* ]]; then
                case "${cmd}" in
                    pause|resume)
                        COMPREPLY=( $(compgen -W "--all $(_kasumi_profiles)" -- "${cur}") )
                        ;;
                    start|stop)
                        ;;
                    *)
                        COMPREPLY=( $(compgen -W "$(_kasumi_profiles)" -- "${cur}") )
                        ;;
                esac
            elif [[ ${cur} == -* ]]; then
                case "${cmd}" in
                    logs)
                        COMPREPLY=( $(compgen -W "--follow -f --lines --full --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    start)
                        COMPREPLY=( $(compgen -W "--autostart --full --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    stop)
                        COMPREPLY=( $(compgen -W "--quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    pause|resume)
                        COMPREPLY=( $(compgen -W "--all --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    key)
                        COMPREPLY=( $(compgen -W "--replace --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    sync)
                        COMPREPLY=( $(compgen -W "--dry-run --initial --audit-inventory --repair --allow-empty-local --bwlimit --concurrency --full --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    status)
                        COMPREPLY=( $(compgen -W "--bwlimit --concurrency --full --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    fsck)
                        COMPREPLY=( $(compgen -W "--bwlimit --concurrency --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    repack)
                        COMPREPLY=( $(compgen -W "--dry-run --reclaim-dirty --bwlimit --concurrency --full --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    resolve-missing)
                        COMPREPLY=( $(compgen -W "--dry-run --confirm --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    *)
                        COMPREPLY=( $(compgen -W "--full --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                esac
            fi
            ;;
    esac
    return 0
}

complete -F _kasumi kasumi
)bash";

        case CompletionShell::Zsh:
            return R"zsh(#compdef kasumi

_kasumi_profiles() {
    local -a profiles
    profiles=(${(f)"$(command kasumi list 2>/dev/null)"})
    _describe 'profile' profiles
}

_kasumi() {
    local -a top_commands profile_cmds daemon_cmds autostart_cmds ignore_cmds remote_cmds gc_cmds shells
    top_commands=(
        'status:Preview pending synchronization changes against remote storage'
        'show:Show profile summary and local traceability'
        'logs:Show or follow daemon logs'
        'start:Start the continuous background sync daemon'
        'stop:Stop the background sync daemon'
        'pause:Pause automated daemon sync for a profile or --all'
        'resume:Resume automated daemon sync for a profile or --all'
        'sync:Synchronize with shared storage'
        'conflicts:List or resolve preserved conflict artifacts'
        'config:Interactive profile and daemon wizard'
        'list:List configured profile names'
        'diagnostics:Inspect local environment and profile health'
        'key:Re-enter and save profile key'
        'profile:Manage profiles non-interactively'
        'daemon:Full daemon subcommands'
        'ignore:Inspect or initialize .kasumiignore rules'
        'fsck:Audit remote integrity'
        'gc:Reclaim eligible remote storage'
        'repack:Consolidate fragmented Micro-Packs'
        'resolve-missing:Resolve missing content as logical deletions'
        'remote:Read-only remote vault inspection'
        'version:Show Kasumi version'
        'help:Show help information'
        'completion:Output shell completion script'
    )
    profile_cmds=(create edit clone storage rename delete test)
    daemon_cmds=(run stop status sync pause resume unlock lock reload logs autostart)
    autostart_cmds=(install uninstall status)
    ignore_cmds=(check init)
    remote_cmds=(heads tree commits summary stat log commit get restore epochs epoch contents content markers objects orphans writers health)
    conflicts_cmds=(resolve)
    gc_cmds=(remove-writer remove-barrier)
    shells=(bash zsh fish powershell)

    if (( CURRENT == 2 )); then
        _describe 'command' top_commands
        return
    fi

    case "${words[2]}" in
        profile)
            if (( CURRENT == 3 )); then
                compadd -- $profile_cmds
            elif (( CURRENT == 4 )) && [[ "${words[3]}" != "create" ]]; then
                _kasumi_profiles
            elif (( CURRENT == 5 )) && [[ "${words[3]}" == "storage" ]]; then
                compadd -- vault file memory
            else
                compadd -- --local --remote --key-storage --min-depth --min-age --bwlimit --clear-bwlimit --concurrency --clear-concurrency --rclone-config --clear-rclone-config --watch --clear-watch --sync-interval --clear-sync-interval --paused --verify --allow-empty-local --confirm --quiet --json --log-file --help
            fi
            ;;
        daemon)
            if (( CURRENT == 3 )); then
                compadd -- $daemon_cmds
            elif (( CURRENT == 4 )) && [[ "${words[CURRENT]}" != -* ]] && [[ "${words[3]}" == "autostart" ]]; then
                compadd -- $autostart_cmds
            elif (( CURRENT == 4 )) && [[ "${words[CURRENT]}" != -* ]] && [[ "${words[3]}" == (status|sync|pause|resume|unlock|lock|logs) ]]; then
                _kasumi_profiles
            else
                compadd -- --background --foreground --wait --lines --full --quiet --json --log-file --help
            fi
            ;;
        ignore)
            if (( CURRENT == 3 )); then
                compadd -- $ignore_cmds
            elif (( CURRENT == 4 )); then
                _kasumi_profiles
            else
                compadd -- --preset --force --dry-run --quiet --json --log-file --help
            fi
            ;;
        remote)
            if (( CURRENT == 3 )); then
                compadd -- $remote_cmds
            elif (( CURRENT == 4 )); then
                _kasumi_profiles
            else
                compadd -- --head --commit --audit --dry-run --bwlimit --concurrency --full --quiet --json --log-file --help
            fi
            ;;
        conflicts)
            if (( CURRENT == 3 )); then
                compadd -- $conflicts_cmds
                _kasumi_profiles
            elif (( CURRENT == 4 )) && [[ "${words[3]}" == "resolve" ]]; then
                _kasumi_profiles
            else
                compadd -- --keep-canonical --keep --dry-run --quiet --json --log-file --help
            fi
            ;;
        gc)
            if (( CURRENT == 3 )); then
                compadd -- $gc_cmds
                _kasumi_profiles
            elif (( CURRENT == 4 )) && [[ "${words[3]}" == remove-* ]]; then
                _kasumi_profiles
            else
                compadd -- --dry-run --min-age --bwlimit --concurrency --confirm-abandoned --quiet --json --log-file --help
            fi
            ;;
        completion)
            (( CURRENT == 3 )) && compadd -- $shells
            ;;
        show|diagnostics|key|sync|status|fsck|repack|resolve-missing|logs|pause|resume)
            if (( CURRENT == 3 )); then
                [[ "${words[2]}" == (pause|resume) ]] && compadd -- --all
                _kasumi_profiles
            else
                compadd -- --follow -f --lines --autostart --all --replace --dry-run --initial --audit-inventory --repair --allow-empty-local --bwlimit --concurrency --reclaim-dirty --confirm --full --quiet --json --log-file --help
            fi
            ;;
        start|stop)
            compadd -- --autostart --full --quiet --json --log-file --help
            ;;
    esac
}

compdef _kasumi kasumi
)zsh";

        case CompletionShell::Fish:
            return R"fish(# Fish completion for kasumi
function __kasumi_profiles
    command kasumi list 2>/dev/null
end

set -l top_cmds status show logs start stop pause resume sync conflicts config list diagnostics key profile daemon ignore fsck gc repack resolve-missing remote version help completion
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "status" -d "Preview pending changes against remote"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "version" -d "Show version"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "help" -d "Show help"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "show" -d "Show profile details"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "logs" -d "Show or follow daemon logs"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "start" -d "Start continuous background sync daemon"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "stop" -d "Stop background sync daemon"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "pause" -d "Pause automated daemon sync"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "resume" -d "Resume automated daemon sync"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "config" -d "Interactive profile and daemon wizard"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "list" -d "List profile names"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "diagnostics" -d "Inspect environment and profile health"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "key" -d "Save or replace profile key"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "profile" -d "Manage profiles non-interactively"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "daemon" -d "Full daemon control subcommands"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "ignore" -d "Inspect or initialize .kasumiignore rules"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "sync" -d "Synchronize with shared storage"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "fsck" -d "Audit remote integrity"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "gc" -d "Run garbage collection"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "repack" -d "Consolidate Micro-Packs"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "resolve-missing" -d "Resolve missing content"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "conflicts" -d "List preserved conflict artifacts"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "remote" -d "Read-only remote inspection"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "completion" -d "Output shell completion script"

complete -c kasumi -f -n "__fish_seen_subcommand_from show diagnostics key sync status fsck repack resolve-missing logs pause resume" -a "(__kasumi_profiles)"
complete -c kasumi -f -n "__fish_seen_subcommand_from pause resume" -a "--all" -d "Target all profiles"
complete -c kasumi -l follow -s f -d "Follow daemon logs live"
complete -c kasumi -l autostart -d "Install user-session autostart on start"
complete -c kasumi -l all -d "Show all commands or target all profiles"
complete -c kasumi -f -n "__fish_seen_subcommand_from conflicts" -a "resolve (__kasumi_profiles)"
complete -c kasumi -f -n "__fish_seen_subcommand_from profile; and not __fish_seen_subcommand_from create edit clone storage rename delete test" -a "create edit clone storage rename delete test"
complete -c kasumi -f -n "__fish_seen_subcommand_from profile; and __fish_seen_subcommand_from edit clone storage rename delete test" -a "(__kasumi_profiles)"
complete -c kasumi -f -n "__fish_seen_subcommand_from daemon; and not __fish_seen_subcommand_from run stop status sync pause resume unlock lock reload logs autostart" -a "run stop status sync pause resume unlock lock reload logs autostart"
complete -c kasumi -f -n "__fish_seen_subcommand_from daemon; and __fish_seen_subcommand_from autostart" -a "install uninstall status"
complete -c kasumi -f -n "__fish_seen_subcommand_from daemon; and __fish_seen_subcommand_from status sync pause resume unlock lock logs" -a "(__kasumi_profiles)"
complete -c kasumi -f -n "__fish_seen_subcommand_from ignore; and not __fish_seen_subcommand_from check init" -a "check init"
complete -c kasumi -f -n "__fish_seen_subcommand_from ignore; and __fish_seen_subcommand_from check init" -a "(__kasumi_profiles)"
complete -c kasumi -f -n "__fish_seen_subcommand_from remote; and not __fish_seen_subcommand_from heads tree commits summary stat log commit get restore epochs epoch contents content markers objects orphans writers health" -a "heads tree commits summary stat log commit get restore epochs epoch contents content markers objects orphans writers health"
complete -c kasumi -f -n "__fish_seen_subcommand_from remote" -a "(__kasumi_profiles)"
complete -c kasumi -f -n "__fish_seen_subcommand_from gc" -a "remove-writer remove-barrier (__kasumi_profiles)"
complete -c kasumi -f -n "__fish_seen_subcommand_from completion" -a "bash zsh fish powershell"

complete -c kasumi -l help -s h -d "Show help"
complete -c kasumi -l version -s v -d "Show version"
complete -c kasumi -l quiet -d "Suppress progress output"
complete -c kasumi -l json -d "Emit JSON output"
complete -c kasumi -l log-file -r -d "Append text or NDJSON logs to file"
complete -c kasumi -l full -d "Show full details"
complete -c kasumi -l background -d "Detach daemon into background"
complete -c kasumi -l foreground -d "Run daemon in foreground"
complete -c kasumi -l wait -d "Wait for triggered daemon sync completion"
complete -c kasumi -l lines -r -d "Maximum daemon log events to display (1-1000)"
complete -c kasumi -l watch -x -a "on off" -d "Enable or disable daemon directory watcher"
complete -c kasumi -l clear-watch -d "Reset daemon watcher setting to default"
complete -c kasumi -l sync-interval -r -d "Daemon fallback sync interval in seconds (0 or 10-86400)"
complete -c kasumi -l clear-sync-interval -d "Reset daemon sync interval to default"
complete -c kasumi -l paused -x -a "on off" -d "Pause or resume automated daemon cycles"
complete -c kasumi -l dry-run -d "Preview without mutating"
complete -c kasumi -l verify -d "Verify remote connectivity/auth after profile create"
complete -c kasumi -l replace -d "Allow replacing an existing different key"
complete -c kasumi -l allow-empty-local -d "Allow missing or empty local directory"
complete -c kasumi -l bwlimit -r -d "Transfer bandwidth limit (e.g. 5M or 5M:2M)"
complete -c kasumi -l concurrency -r -d "Transfer concurrency (1-16)"
complete -c kasumi -l rclone-config -r -d "Custom rclone.conf path"
complete -c kasumi -l preset -x -a "default dev office minimal" -d ".kasumiignore preset"
complete -c kasumi -l force -d "Overwrite existing file"
complete -c kasumi -l keep-canonical -d "Keep canonical file on conflict resolve"
complete -c kasumi -l keep -d "Select conflict artifact to promote"
complete -c kasumi -l commit -d "Target reachable commit ID"
)fish";

        case CompletionShell::PowerShell:
            return R"ps1(# PowerShell argument completer for kasumi
Register-ArgumentCompleter -Native -CommandName kasumi -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $tokens = $commandAst.CommandElements | ForEach-Object { $_.Extent.Text }
    $count = $tokens.Count
    if ($wordToComplete -eq '') { $count++ }

    $topCommands = @('status', 'show', 'logs', 'start', 'stop', 'pause', 'resume', 'sync', 'conflicts', 'config', 'list', 'diagnostics', 'key', 'profile', 'daemon', 'ignore', 'fsck', 'gc', 'repack', 'resolve-missing', 'remote', 'version', 'help', 'completion')
    $profileSubs = @('create', 'edit', 'clone', 'storage', 'rename', 'delete', 'test')
    $daemonSubs = @('run', 'stop', 'status', 'sync', 'pause', 'resume', 'unlock', 'lock', 'reload', 'logs', 'autostart')
    $autostartSubs = @('install', 'uninstall', 'status')
    $ignoreSubs = @('check', 'init')
    $remoteSubs = @('heads', 'tree', 'commits', 'summary', 'stat', 'log', 'commit', 'get', 'restore', 'epochs', 'epoch', 'contents', 'content', 'markers', 'objects', 'orphans', 'writers', 'health')
    $conflictsSubs = @('resolve')
    $gcSubs = @('remove-writer', 'remove-barrier')
    $shells = @('bash', 'zsh', 'fish', 'powershell')

    $getProfiles = {
        try {
            & kasumi list 2>$null | Where-Object { $_ }
        } catch {
            @()
        }
    }

    $candidates = @()
    if ($count -le 2) {
        $candidates = $topCommands
    } else {
        $cmd = $tokens[1]
        switch ($cmd) {
            'profile' {
                if ($count -eq 3) {
                    $candidates = $profileSubs
                } elseif ($count -eq 4 -and $tokens[2] -ne 'create') {
                    $candidates = & $getProfiles
                } elseif ($count -eq 5 -and $tokens[2] -eq 'storage') {
                    $candidates = @('vault', 'file', 'memory')
                } elseif ($wordToComplete -like '-*') {
                    $candidates = @('--local', '--remote', '--key-storage', '--min-depth', '--min-age', '--bwlimit', '--clear-bwlimit', '--concurrency', '--clear-concurrency', '--rclone-config', '--clear-rclone-config', '--watch', '--clear-watch', '--sync-interval', '--clear-sync-interval', '--paused', '--verify', '--allow-empty-local', '--confirm', '--quiet', '--json', '--log-file', '--help')
                }
            }
            'daemon' {
                if ($count -eq 3) {
                    $candidates = $daemonSubs
                } elseif ($count -eq 4 -and -not ($wordToComplete -like '-*') -and $tokens[2] -eq 'autostart') {
                    $candidates = $autostartSubs
                } elseif ($count -eq 4 -and -not ($wordToComplete -like '-*') -and $tokens[2] -in @('status', 'sync', 'pause', 'resume', 'unlock', 'lock', 'logs')) {
                    $candidates = & $getProfiles
                } elseif ($wordToComplete -like '-*') {
                    $candidates = @('--background', '--foreground', '--wait', '--lines', '--full', '--quiet', '--json', '--log-file', '--help')
                }
            }
            'ignore' {
                if ($count -eq 3) {
                    $candidates = $ignoreSubs
                } elseif ($count -eq 4) {
                    $candidates = & $getProfiles
                } elseif ($wordToComplete -like '-*') {
                    $candidates = @('--preset', '--force', '--dry-run', '--quiet', '--json', '--log-file', '--help')
                }
            }
            'remote' {
                if ($count -eq 3) {
                    $candidates = $remoteSubs
                } elseif ($count -eq 4) {
                    $candidates = & $getProfiles
                } elseif ($wordToComplete -like '-*') {
                    $candidates = @('--head', '--commit', '--audit', '--dry-run', '--bwlimit', '--concurrency', '--full', '--quiet', '--json', '--log-file', '--help')
                }
            }
            'conflicts' {
                if ($count -eq 3) {
                    $candidates = $conflictsSubs + (& $getProfiles)
                } elseif ($count -eq 4 -and $tokens[2] -eq 'resolve') {
                    $candidates = & $getProfiles
                } elseif ($wordToComplete -like '-*') {
                    $candidates = @('--keep-canonical', '--keep', '--dry-run', '--quiet', '--json', '--log-file', '--help')
                }
            }
            'gc' {
                if ($count -eq 3) {
                    $candidates = $gcSubs + (& $getProfiles)
                } elseif ($count -eq 4 -and $tokens[2] -like 'remove-*') {
                    $candidates = & $getProfiles
                } elseif ($wordToComplete -like '-*') {
                    $candidates = @('--dry-run', '--min-age', '--bwlimit', '--concurrency', '--confirm-abandoned', '--quiet', '--json', '--log-file', '--help')
                }
            }
            'completion' {
                if ($count -eq 3) { $candidates = $shells }
            }
            default {
                if ($count -eq 3 -and $cmd -in @('show', 'diagnostics', 'key', 'sync', 'status', 'fsck', 'repack', 'resolve-missing', 'logs', 'pause', 'resume')) {
                    $candidates = & $getProfiles
                    if ($cmd -in @('pause', 'resume')) { $candidates += '--all' }
                } elseif ($wordToComplete -like '-*') {
                    $candidates = @('--follow', '-f', '--lines', '--autostart', '--all', '--replace', '--dry-run', '--initial', '--audit-inventory', '--repair', '--allow-empty-local', '--bwlimit', '--concurrency', '--reclaim-dirty', '--confirm', '--full', '--quiet', '--json', '--log-file', '--help')
                }
            }
        }
    }

    $candidates | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
)ps1";
    }
    return {};
}

} // namespace kasumi::cli

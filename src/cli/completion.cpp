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

    local top_commands="config list show diagnostics key profile sync status fsck gc repack resolve-missing conflicts remote completion"
    local profile_cmds="create edit clone storage rename delete"
    local gc_cmds="remove-writer remove-barrier"
    local remote_cmds="heads tree commits summary stat commit get epochs epoch contents content markers objects orphans writers health"
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
                    edit|clone|storage|rename|delete)
                        COMPREPLY=( $(compgen -W "$(_kasumi_profiles)" -- "${cur}") )
                        ;;
                esac
            elif [[ ${COMP_CWORD} -eq 4 && "${COMP_WORDS[2]}" == "storage" ]]; then
                COMPREPLY=( $(compgen -W "vault file memory" -- "${cur}") )
            elif [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "--local --remote --key-storage --min-depth --min-age --confirm --quiet --json --log-file --help" -- "${cur}") )
            fi
            ;;
        gc)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${gc_cmds} $(_kasumi_profiles)" -- "${cur}") )
            elif [[ ${COMP_CWORD} -eq 3 && ( "${COMP_WORDS[2]}" == "remove-writer" || "${COMP_WORDS[2]}" == "remove-barrier" ) ]]; then
                COMPREPLY=( $(compgen -W "$(_kasumi_profiles)" -- "${cur}") )
            elif [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "--dry-run --min-age --confirm-abandoned --quiet --json --log-file --help" -- "${cur}") )
            fi
            ;;
        remote)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${remote_cmds}" -- "${cur}") )
            elif [[ ${COMP_CWORD} -eq 3 ]]; then
                COMPREPLY=( $(compgen -W "$(_kasumi_profiles)" -- "${cur}") )
            elif [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "--head --commit --audit --full --quiet --json --log-file --help" -- "${cur}") )
            fi
            ;;
        completion)
            if [[ ${COMP_CWORD} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "${shells}" -- "${cur}") )
            fi
            ;;
        show|diagnostics|key|sync|status|fsck|repack|resolve-missing|conflicts)
            if [[ ${COMP_CWORD} -eq 2 && ${cur} != -* ]]; then
                COMPREPLY=( $(compgen -W "$(_kasumi_profiles)" -- "${cur}") )
            elif [[ ${cur} == -* ]]; then
                case "${cmd}" in
                    sync)
                        COMPREPLY=( $(compgen -W "--dry-run --initial --audit-inventory --repair --full --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    status)
                        COMPREPLY=( $(compgen -W "--full --quiet --json --log-file --help" -- "${cur}") )
                        ;;
                    repack)
                        COMPREPLY=( $(compgen -W "--dry-run --reclaim-dirty --full --quiet --json --log-file --help" -- "${cur}") )
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
    local -a top_commands profile_cmds remote_cmds gc_cmds shells
    top_commands=(
        'config:Interactive profile wizard'
        'list:List configured profile names'
        'show:Show profile details and local traceability'
        'diagnostics:Inspect local environment and profile health'
        'key:Re-enter and save profile key'
        'profile:Manage profiles non-interactively'
        'sync:Synchronize with shared storage'
        'status:Show pending synchronization changes'
        'fsck:Audit remote integrity'
        'gc:Reclaim eligible remote storage'
        'repack:Consolidate fragmented Micro-Packs'
        'resolve-missing:Resolve missing content as logical deletions'
        'conflicts:List preserved conflict artifacts'
        'remote:Read-only remote vault inspection'
        'completion:Output shell completion script'
    )
    profile_cmds=(create edit clone storage rename delete)
    remote_cmds=(heads tree commits summary stat commit get epochs epoch contents content markers objects orphans writers health)
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
                compadd -- --local --remote --key-storage --min-depth --min-age --confirm --quiet --json --log-file --help
            fi
            ;;
        remote)
            if (( CURRENT == 3 )); then
                compadd -- $remote_cmds
            elif (( CURRENT == 4 )); then
                _kasumi_profiles
            else
                compadd -- --head --commit --audit --full --quiet --json --log-file --help
            fi
            ;;
        gc)
            if (( CURRENT == 3 )); then
                compadd -- $gc_cmds
                _kasumi_profiles
            elif (( CURRENT == 4 )) && [[ "${words[3]}" == remove-* ]]; then
                _kasumi_profiles
            else
                compadd -- --dry-run --min-age --confirm-abandoned --quiet --json --log-file --help
            fi
            ;;
        completion)
            (( CURRENT == 3 )) && compadd -- $shells
            ;;
        show|diagnostics|key|sync|status|fsck|repack|resolve-missing|conflicts)
            if (( CURRENT == 3 )); then
                _kasumi_profiles
            else
                compadd -- --dry-run --initial --audit-inventory --repair --reclaim-dirty --confirm --full --quiet --json --log-file --help
            fi
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

set -l top_cmds config list show diagnostics key profile sync status fsck gc repack resolve-missing conflicts remote completion
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "config" -d "Interactive profile wizard"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "list" -d "List profile names"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "show" -d "Show profile details"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "diagnostics" -d "Inspect environment and profile health"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "key" -d "Save or replace profile key"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "profile" -d "Manage profiles non-interactively"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "sync" -d "Synchronize with shared storage"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "status" -d "Show pending changes"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "fsck" -d "Audit remote integrity"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "gc" -d "Run garbage collection"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "repack" -d "Consolidate Micro-Packs"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "resolve-missing" -d "Resolve missing content"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "conflicts" -d "List preserved conflict artifacts"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "remote" -d "Read-only remote inspection"
complete -c kasumi -f -n "not __fish_seen_subcommand_from $top_cmds" -a "completion" -d "Output shell completion script"

complete -c kasumi -f -n "__fish_seen_subcommand_from show diagnostics key sync status fsck repack resolve-missing conflicts" -a "(__kasumi_profiles)"
complete -c kasumi -f -n "__fish_seen_subcommand_from profile; and not __fish_seen_subcommand_from create edit clone storage rename delete" -a "create edit clone storage rename delete"
complete -c kasumi -f -n "__fish_seen_subcommand_from profile; and __fish_seen_subcommand_from edit clone storage rename delete" -a "(__kasumi_profiles)"
complete -c kasumi -f -n "__fish_seen_subcommand_from remote; and not __fish_seen_subcommand_from heads tree commits summary stat commit get epochs epoch contents content markers objects orphans writers health" -a "heads tree commits summary stat commit get epochs epoch contents content markers objects orphans writers health"
complete -c kasumi -f -n "__fish_seen_subcommand_from remote" -a "(__kasumi_profiles)"
complete -c kasumi -f -n "__fish_seen_subcommand_from gc" -a "remove-writer remove-barrier (__kasumi_profiles)"
complete -c kasumi -f -n "__fish_seen_subcommand_from completion" -a "bash zsh fish powershell"

complete -c kasumi -l help -s h -d "Show help"
complete -c kasumi -l version -s v -d "Show version"
complete -c kasumi -l quiet -d "Suppress progress output"
complete -c kasumi -l json -d "Emit JSON output"
complete -c kasumi -l full -d "Show full details"
complete -c kasumi -l dry-run -d "Preview without mutating"
complete -c kasumi -l commit -d "Target reachable commit ID"
)fish";

        case CompletionShell::PowerShell:
            return R"ps1(# PowerShell argument completer for kasumi
Register-ArgumentCompleter -Native -CommandName kasumi -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $tokens = $commandAst.CommandElements | ForEach-Object { $_.Extent.Text }
    $count = $tokens.Count
    if ($wordToComplete -eq '') { $count++ }

    $topCommands = @('config', 'list', 'show', 'diagnostics', 'key', 'profile', 'sync', 'status', 'fsck', 'gc', 'repack', 'resolve-missing', 'conflicts', 'remote', 'completion')
    $profileSubs = @('create', 'edit', 'clone', 'storage', 'rename', 'delete')
    $remoteSubs = @('heads', 'tree', 'commits', 'summary', 'stat', 'commit', 'get', 'epochs', 'epoch', 'contents', 'content', 'markers', 'objects', 'orphans', 'writers', 'health')
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
                    $candidates = @('--local', '--remote', '--key-storage', '--min-depth', '--min-age', '--confirm', '--quiet', '--json', '--log-file', '--help')
                }
            }
            'remote' {
                if ($count -eq 3) {
                    $candidates = $remoteSubs
                } elseif ($count -eq 4) {
                    $candidates = & $getProfiles
                } elseif ($wordToComplete -like '-*') {
                    $candidates = @('--head', '--commit', '--audit', '--full', '--quiet', '--json', '--log-file', '--help')
                }
            }
            'gc' {
                if ($count -eq 3) {
                    $candidates = $gcSubs + (& $getProfiles)
                } elseif ($count -eq 4 -and $tokens[2] -like 'remove-*') {
                    $candidates = & $getProfiles
                } elseif ($wordToComplete -like '-*') {
                    $candidates = @('--dry-run', '--min-age', '--confirm-abandoned', '--quiet', '--json', '--log-file', '--help')
                }
            }
            'completion' {
                if ($count -eq 3) { $candidates = $shells }
            }
            default {
                if ($count -eq 3 -and $cmd -in @('show', 'diagnostics', 'key', 'sync', 'status', 'fsck', 'repack', 'resolve-missing', 'conflicts')) {
                    $candidates = & $getProfiles
                } elseif ($wordToComplete -like '-*') {
                    $candidates = @('--dry-run', '--initial', '--audit-inventory', '--repair', '--reclaim-dirty', '--confirm', '--full', '--quiet', '--json', '--log-file', '--help')
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

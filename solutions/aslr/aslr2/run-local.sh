#!/bin/sh
set -eu

usage() {
    echo "usage: $0 [--flag FLAG] [--no-aslr] [PROGRAM [ARG ...]]" >&2
    exit 2
}

flag='SNH{local}'
write_flag=false
no_aslr=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        --flag)
            [ "$#" -ge 2 ] || usage
            flag=$2
            write_flag=true
            shift 2
            ;;
        --no-aslr)
            no_aslr=true
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            usage
            ;;
        *)
            break
            ;;
    esac
done

[ "$(printf '%s\n' "$flag" | wc -l)" -eq 1 ] || {
    echo "local flag must be a single line" >&2
    exit 2
}

# Run from the distribution root so relative challenge data (for example
# flag.txt and poem) is found regardless of where this script was invoked.
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ "$#" -eq 0 ]; then
    set -- "./${PWD##*/}"
fi
if [ "$write_flag" = true ] || [ ! -e flag.txt ]; then
    printf '%s\n' "$flag" > flag.txt
fi

if [ "$no_aslr" = true ]; then
    command -v setarch >/dev/null 2>&1 || {
        echo "--no-aslr requires setarch" >&2
        exit 1
    }
    exec setarch "$(uname -m)" -R "$@"
fi
exec "$@"

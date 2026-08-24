#!/bin/sh
set -eu

BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ANDROID_HOME=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
API=${API:-36}

if [ -z "$ANDROID_HOME" ]; then
    for candidate in /usr/local/share/android-commandlinetools "$HOME/Library/Android/sdk"; do
        if [ -f "$candidate/platforms/android-$API/android.jar" ]; then
            ANDROID_HOME=$candidate
            break
        fi
    done
fi

[ -n "$ANDROID_HOME" ] || {
    echo "Set ANDROID_HOME (or ANDROID_SDK_ROOT) to an Android SDK" >&2
    exit 1
}

ANDROID_JAR="$ANDROID_HOME/platforms/android-$API/android.jar"
if [ -z "${BUILD_TOOLS:-}" ]; then
    BUILD_TOOLS=
    for candidate in "$ANDROID_HOME"/build-tools/*; do
        [ -x "$candidate/d8" ] || continue
        BUILD_TOOLS=$candidate
    done
fi
D8="$BUILD_TOOLS/d8"
OUT="$BASE/build"

[ -f "$ANDROID_JAR" ] || { echo "Missing $ANDROID_JAR" >&2; exit 1; }
[ -x "$D8" ] || { echo "Missing d8 under $BUILD_TOOLS" >&2; exit 1; }
if [ -z "${JAVAC:-}" ]; then
    JAVAC=javac
    if ! "$JAVAC" -version >/dev/null 2>&1 && command -v brew >/dev/null 2>&1; then
        for formula in openjdk@17 openjdk@21 openjdk; do
            candidate=$(brew --prefix "$formula" 2>/dev/null || true)/bin/javac
            if [ -x "$candidate" ]; then
                JAVAC=$candidate
                break
            fi
        done
    fi
fi
command -v "$JAVAC" >/dev/null || { echo "$JAVAC is required" >&2; exit 1; }

rm -rf "$OUT"
mkdir -p "$OUT/classes" "$OUT/dex"
"$JAVAC" -version >/dev/null 2>&1 || {
    echo "javac is installed but no working JDK runtime was found" >&2
    exit 1
}
JAVA_HOME=${JAVA_HOME:-$(CDPATH= cd -- "$(dirname -- "$JAVAC")/.." && pwd)}
export JAVA_HOME
"$JAVAC" -source 8 -target 8 -classpath "$ANDROID_JAR" \
    -d "$OUT/classes" "$BASE/CarrierUnlock.java"
"$D8" --min-api 26 --lib "$ANDROID_JAR" --output "$OUT/dex" \
    "$OUT/classes/CarrierUnlock.class"
(cd "$OUT/dex" && zip -q "$BASE/carrier-unlock.jar" classes.dex)
echo "Built $BASE/carrier-unlock.jar"

-keep class dev.alsatianconsulting.pocketpcap.** { *; }

# tun2socks' gomobile binding. Go calls back into these classes from native code
# by name through JNI, so R8 full mode renaming or dropping any of them breaks the
# rootless VPN path in release builds only. app/libs/tun2socks.aar carries the same
# two rules in its own proguard.txt; they are repeated here because that archive is
# a local file dependency, and a consumer rule that silently stops being applied
# would fail at runtime rather than at build time.
-keep class go.** { *; }
-keep class engine.** { *; }

# UniFFI's JNA bridge has desktop-only overloads that reference java.awt.
# Android never calls them, but R8 still resolves their signatures.
-dontwarn java.awt.**

# Preserve the generated bridge and JNA's reflective native symbol mapping.
-keep class uniffi.quantumlink_mobile.** { *; }
-keep class com.sun.jna.** { *; }

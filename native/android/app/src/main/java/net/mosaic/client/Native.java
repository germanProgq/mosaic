package net.mosaic.client;

final class Native {
    static { System.loadLibrary("mosaic_jni"); }
    static native boolean validate(byte[] profile);
    static native long start(byte[] profile, String storage);
    static native void stop(long handle);
    static native int socket(long handle);
    static native void socketReady(long handle, int socket, boolean ready);
    static native boolean bindNetwork(int socket, long network);
    static native boolean needsNetwork(long handle);
    static native void networkReady(long handle, boolean ready);
    static native void pathChanged(long handle);
    static native String settings(long handle);
    static native String status(long handle);
    static native void writePacket(long handle, byte[] bytes, int length);
    static native int readPacket(long handle, byte[] bytes);
}
